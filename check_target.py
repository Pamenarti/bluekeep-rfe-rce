#!/usr/bin/env python3

import sys
import socket
import argparse

def check_rdp_port(host, port=3389, timeout=3):
    """Check if the target host has the RDP port open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return True
        else:
            return False
    except socket.error as e:
        print(f"[-] Error checking target: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Check if a target has RDP port open.")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Target port (default: 3389)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Connection timeout in seconds (default: 3)")
    args = parser.parse_args()
    
    print(f"[*] Checking if {args.ip}:{args.port} has RDP service running...")
    
    if check_rdp_port(args.ip, args.port, args.timeout):
        print(f"[+] Success! RDP port {args.port} is open on {args.ip}")
        return 0
    else:
        print(f"[-] Failed. RDP port {args.port} appears to be closed on {args.ip}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
