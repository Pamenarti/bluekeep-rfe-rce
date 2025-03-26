#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import threading
import time
import socket
from pathlib import Path

def start_rdp_simulator(port=3389, verbose=False):
    """Start the RDP simulator in a separate thread."""
    print(f"[*] Starting RDP simulator on port {port}...")
    
    # Check if rdp_listener.py exists
    simulator_path = Path("rdp_listener.py")
    if not simulator_path.exists():
        print("[-] RDP simulator script not found!")
        return None
    
    # Build command to start the simulator
    cmd = ["python3", str(simulator_path), "-p", str(port)]
    if verbose:
        cmd.append("-v")
    
    # Start the simulator in a new process
    try:
        # Using PIPE for stdout to avoid blocking the main thread
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Give the simulator time to start
        time.sleep(2)
        
        # Check if the simulator is running by trying to connect to it
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            
            if result == 0:
                print("[+] RDP simulator started successfully")
                return process
            else:
                print("[-] Failed to start RDP simulator")
                process.terminate()
                return None
        except socket.error:
            print("[-] Failed to connect to RDP simulator")
            process.terminate()
            return None
            
    except Exception as e:
        print(f"[-] Error starting RDP simulator: {e}")
        return None

def run_exploit_against_simulator(mode="poc", port=3389, verbose=False):
    """Run the BlueKeep exploit against the local simulator."""
    print(f"[*] Running BlueKeep {mode.upper()} exploit against local simulator...")
    
    # Determine which script to use
    if mode == "poc":
        exploit_path = Path("bluekeep_poc.py")
        runner_path = Path("local_bluekeep_runner.py")
    else:  # dos mode
        exploit_path = Path("bluekeep_dos.py")
        runner_path = Path("local_bluekeep_runner.py")
    
    # Check if the exploit script exists
    if not exploit_path.exists():
        print(f"[-] Exploit script {exploit_path} not found!")
        return False
        
    # Check if the runner script exists
    if not runner_path.exists():
        print(f"[-] Runner script {runner_path} not found!")
        return False
    
    # Build command to run the exploit
    cmd = ["python3", str(runner_path), "-i", "127.0.0.1", "-p", str(port), "-m", mode]
    if verbose:
        cmd.append("-v")
    
    # Run the exploit
    try:
        process = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Print the output
        print(process.stdout)
        if process.stderr:
            print(process.stderr)
            
        return process.returncode == 0
        
    except Exception as e:
        print(f"[-] Error running exploit: {e}")
        return False

def main():
    banner = """
    ____  __           __ __                 
   / __ )/ /_  _____  / //_/__  ___ ____     
  / __  / / / / / _ \/ ,< / _ \/ -_) __/     
 /_/ /_/_/\_,_/_//_/_/|_|\___/\__/_/        
                                              
 BlueKeep Test Environment - Self Test Tool
 """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description="BlueKeep Self Test Tool")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Port to use for testing (default: 3389)")
    parser.add_argument("-m", "--mode", choices=["poc", "dos"], default="poc", 
                        help="Exploit mode: 'poc' for proof of concept or 'dos' for denial of service (default: poc)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Display configuration
    print(f"[*] Test port: {args.port}")
    print(f"[*] Test mode: {args.mode.upper()}")
    print(f"[*] Verbose: {'Yes' if args.verbose else 'No'}")
    print()
    
    try:
        # Step 1: Start the RDP simulator
        simulator_process = start_rdp_simulator(args.port, args.verbose)
        if simulator_process is None:
            print("[-] Failed to start RDP simulator. Exiting.")
            sys.exit(1)
        
        # Step 2: Run the exploit against the simulator
        print("\n[*] Running exploit against simulator...\n")
        try:
            success = run_exploit_against_simulator(args.mode, args.port, args.verbose)
            
            if success:
                print("\n[+] Self-test completed successfully!")
            else:
                print("\n[-] Self-test failed!")
                
        finally:
            # Step 3: Clean up - stop the simulator
            print("\n[*] Stopping RDP simulator...")
            simulator_process.terminate()
            try:
                simulator_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                simulator_process.kill()
                
            print("[+] RDP simulator stopped")
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
