#!/usr/bin/env python3

import sys
import os
import socket
import struct
import argparse
import time
import subprocess
from pathlib import Path

def check_rdp_port(host, port=3389, timeout=3):
    """Check if the target host has the RDP port open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        return result == 0
    except socket.error as e:
        print(f"[-] Error checking target {host}: {e}")
        return False

def run_metasploit_scanner(target_ip, port=3389):
    """Run Metasploit scanner to detect BlueKeep vulnerability."""
    print(f"[*] Scanning {target_ip}:{port} for BlueKeep vulnerability...")

    # Create resource script for scanner
    resource_file = "bluekeep_scan.rc"
    with open(resource_file, "w") as f:
        f.write("use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\n")
        f.write(f"set RHOSTS {target_ip}\n")
        f.write(f"set RPORT {port}\n")
        f.write("run\n")
        f.write("exit\n")
    
    try:
        # Run Metasploit with the resource script
        print("[*] Running Metasploit scanner...")
        cmd = ["msfconsole", "-q", "-r", resource_file]
        process = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Remove resource file
        if os.path.exists(resource_file):
            os.remove(resource_file)
        
        # Check output for vulnerability detection
        if "VULNERABLE" in process.stdout:
            print(f"[+] {target_ip}:{port} is VULNERABLE to BlueKeep!")
            print("[*] You can now exploit this target with:")
            print(f"    python3 metasploit_bluekeep.py -i {target_ip} -t 2")
            return True
        elif "The target is not exploitable" in process.stdout:
            print(f"[-] {target_ip}:{port} is NOT vulnerable to BlueKeep")
            return False
        else:
            print(f"[?] Could not determine if {target_ip}:{port} is vulnerable")
            print("[*] Scanner output:")
            print(process.stdout)
            return None
    
    except FileNotFoundError:
        print("[-] Error: Metasploit Framework (msfconsole) not found")
        print("[*] Please install Metasploit Framework first")
        return None
    except Exception as e:
        print(f"[-] Error running scanner: {e}")
        return None

def scan_from_file(filename, port=3389):
    """Scan multiple IPs from a file."""
    print(f"[*] Loading targets from {filename}")
    try:
        with open(filename, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        print(f"[*] Loaded {len(targets)} targets")
        vulnerable_targets = []
        
        for target in targets:
            print(f"\n[*] Checking {target}...")
            if check_rdp_port(target, port):
                print(f"[+] RDP port open on {target}:{port}")
                result = run_metasploit_scanner(target, port)
                if result:
                    vulnerable_targets.append(target)
            else:
                print(f"[-] No RDP service detected on {target}:{port}")
        
        if vulnerable_targets:
            print(f"\n[+] Found {len(vulnerable_targets)} vulnerable targets:")
            for target in vulnerable_targets:
                print(f"    - {target}")
            
            # Save vulnerable targets to file
            with open("vulnerable_targets.txt", "w") as f:
                for target in vulnerable_targets:
                    f.write(f"{target}\n")
            print("[+] Vulnerable targets saved to 'vulnerable_targets.txt'")
        else:
            print("\n[-] No vulnerable targets found")
    
    except FileNotFoundError:
        print(f"[-] File not found: {filename}")
    except Exception as e:
        print(f"[-] Error processing file: {e}")

def main():
    banner = """
    ____  __           __ __                _____                                  
   / __ )/ /_  _____  / //_/__  ___ ____   / ___/________ _____  ____  ___  ____  
  / __  / / / / / _ \/ ,< / _ \/ -_) __/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ __ \ 
 / /_/ / /___/ /  __/ /| /  __/\__/_/     ___/ / /__/ /_/ / / / / / / /  __/ / / /
/_____/_____/_/\___/_/ |_\___/           /____/\___/\__,_/_/ /_/_/ /_/\___/_/ /_/ 
                                                                                  
 CVE-2019-0708 BlueKeep Vulnerability Scanner
 """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description="BlueKeep Vulnerability Scanner")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-i", "--ip", help="Target IP address")
    target_group.add_argument("-f", "--file", help="File containing target IP addresses, one per line")
    
    parser.add_argument("-p", "--port", type=int, default=3389, help="Target port (default: 3389)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    try:
        if args.ip:
            # Scan single IP
            if check_rdp_port(args.ip, args.port):
                print(f"[+] RDP port open on {args.ip}:{args.port}")
                run_metasploit_scanner(args.ip, args.port)
            else:
                print(f"[-] No RDP service detected on {args.ip}:{args.port}")
        else:
            # Scan multiple IPs from file
            scan_from_file(args.file, args.port)
            
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
