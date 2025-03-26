#!/usr/bin/env python3

import sys
import socket
import struct
import argparse
import subprocess
import binascii
import time
from pathlib import Path

def basic_port_check(host, port=3389, timeout=3):
    """Perform a basic TCP port check to see if the port is open."""
    try:
        print(f"[*] Testing basic TCP connectivity to {host}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN on {host}")
            sock.close()
            return True
        else:
            print(f"[-] Port {port} is CLOSED on {host}")
            return False
    except socket.error as e:
        print(f"[-] Socket error when checking {host}: {e}")
        return False

def send_rdp_probe(host, port=3389, timeout=5):
    """Send an RDP protocol handshake to verify if RDP is running on the port."""
    # Standard RDP connection request (partial)
    rdp_probe = bytes.fromhex("0300000b06e00000000000")
    
    try:
        print(f"[*] Sending RDP protocol probe to {host}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(rdp_probe)
        
        try:
            response = sock.recv(1024)
            sock.close()
            
            if response:
                print(f"[+] Received RDP response: {len(response)} bytes")
                print(f"[+] Response hex: {response.hex()}")
                
                # Check if it's a valid RDP response
                if response[0:1] == b'\x03': # RDP usually starts with 0x03
                    print(f"[+] Valid RDP service detected on {host}:{port}")
                    return True
                else:
                    print(f"[?] Response received but doesn't appear to be RDP")
                    return False
            else:
                print(f"[-] No response received from {host}:{port}")
                return False
        except socket.timeout:
            print(f"[-] Timeout while waiting for response from {host}:{port}")
            sock.close()
            return False
            
    except Exception as e:
        print(f"[-] Error during RDP probe: {e}")
        return False

def nmap_rdp_check(host, port=3389):
    """Use nmap to perform advanced RDP service detection."""
    try:
        if not Path("/usr/bin/nmap").exists():
            print("[!] Nmap not found, skipping advanced scan")
            return None
            
        print(f"[*] Running nmap service detection on {host}:{port}...")
        cmd = ["nmap", "-sV", "-p", str(port), "--script=rdp-enum-encryption", host]
        
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if "microsoft-rdp" in process.stdout.lower() or "ms-rdp" in process.stdout.lower():
            print(f"[+] Nmap confirms RDP service on {host}:{port}")
            print(f"[*] Service details:")
            for line in process.stdout.splitlines():
                if "open" in line or "rdp" in line.lower():
                    print(f"    {line.strip()}")
            return True
        else:
            print(f"[-] Nmap could not confirm RDP service on {host}:{port}")
            return False
            
    except Exception as e:
        print(f"[-] Error during nmap scan: {e}")
        return None

def verify_rdp_vulnerability(host, port=3389):
    """Check if the target is vulnerable to BlueKeep using Metasploit scanner."""
    try:
        print(f"[*] Checking BlueKeep vulnerability on {host}:{port}...")
        
        resource_file = "vuln_check.rc"
        with open(resource_file, "w") as f:
            f.write("use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\n")
            f.write(f"set RHOSTS {host}\n")
            f.write(f"set RPORT {port}\n")
            f.write("run\n")
            f.write("exit\n")
        
        cmd = ["msfconsole", "-q", "-r", resource_file]
        process = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, 
            text=True
        )
        
        if os.path.exists(resource_file):
            os.remove(resource_file)
        
        if "VULNERABLE" in process.stdout:
            print(f"[+] {host}:{port} is VULNERABLE to BlueKeep!")
            return True
        elif "The target is not exploitable" in process.stdout:
            print(f"[-] {host}:{port} is NOT vulnerable to BlueKeep")
            return False
        else:
            print(f"[?] Vulnerability status uncertain for {host}:{port}")
            return None
            
    except Exception as e:
        print(f"[-] Error checking vulnerability: {e}")
        return None

def run_comprehensive_check(host, port=3389):
    """Run a comprehensive RDP check."""
    print(f"\n{'='*60}")
    print(f" Comprehensive RDP Check for {host}:{port}")
    print(f"{'='*60}\n")
    
    # Step 1: Basic port check
    port_open = basic_port_check(host, port)
    if not port_open:
        print(f"[-] Port {port} is not open on {host}. RDP service is not accessible.")
        return False
    
    # Step 2: Protocol probe
    rdp_detected = send_rdp_probe(host, port)
    if not rdp_detected:
        print(f"[!] Warning: Port {port} is open but doesn't appear to be running RDP")
    
    # Step 3: Nmap verification (if available)
    nmap_result = nmap_rdp_check(host, port)
    
    # Step 4: Vulnerability check (only if we think RDP is running)
    if rdp_detected or (nmap_result is True):
        print(f"\n[*] RDP service confirmed, checking vulnerability...")
        is_vulnerable = verify_rdp_vulnerability(host, port)
        
        print(f"\n{'='*60}")
        print(f" Summary for {host}:{port}")
        print(f"{'='*60}")
        print(f"Port open: {'Yes' if port_open else 'No'}")
        print(f"RDP protocol detected: {'Yes' if rdp_detected else 'No'}")
        print(f"Nmap RDP verification: {'Yes' if nmap_result is True else 'No' if nmap_result is False else 'Not performed'}")
        print(f"BlueKeep vulnerability: {'Yes' if is_vulnerable is True else 'No' if is_vulnerable is False else 'Uncertain'}")
        
        # Overall assessment
        if is_vulnerable is True:
            print(f"\n[+] OVERALL: Target is VULNERABLE to BlueKeep!")
            return True
        elif rdp_detected and is_vulnerable is False:
            print(f"\n[-] OVERALL: Target has RDP but is NOT vulnerable to BlueKeep")
            return False
        else:
            print(f"\n[?] OVERALL: Target status is UNCERTAIN, manual verification recommended")
            return None
    else:
        print(f"\n[-] OVERALL: No RDP service detected on {host}:{port}")
        return False

def main():
    banner = """
    ____  ____  ____     __          __               __   
   / __ \/ __ \/ __ \   / /___ _____/ /_  ___  _____/ /__ 
  / /_/ / / / / /_/ /  / / __ `/ __  / / / / |/_/ __  / _ \\
 / _, _/ /_/ / ____/  / / /_/ / /_/ / /_/ />  </ /_/ /  __/
/_/ |_/_____/_/      /_/\__,_/\__,_/\__,_/_/|_|\__,_/\___/ 
                                                          
 BlueKeep RDP Service & Vulnerability Detector
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description="Detailed RDP Service & Vulnerability Checker")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Target port (default: 3389)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    try:
        success = run_comprehensive_check(args.ip, args.port)
        if success:
            print("\n[+] Target appears ready for exploitation")
            print(f"    Try: python3 metasploit_bluekeep.py -i {args.ip} -A")
            return 0
        elif success is False:
            print("\n[-] Target does not appear to be exploitable")
            print("    If you want to try anyway, use the force option:")
            print(f"    python3 force_bluekeep.py -i {args.ip}")
            return 1
        else:
            print("\n[?] Target status uncertain")
            print("    You may still try to exploit with force option:")
            print(f"    python3 force_bluekeep.py -i {args.ip}")
            return 2
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        return 3
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {str(e)}")
        return 4

if __name__ == "__main__":
    import os
    sys.exit(main())
