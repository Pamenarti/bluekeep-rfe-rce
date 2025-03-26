#!/usr/bin/env python3

import socket
import sys
import threading
import argparse
import time
import os

class RDPSimulator:
    def __init__(self, host="0.0.0.0", port=3389, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.running = False
        self.socket = None
        self.connections = []
        
    def log(self, message):
        """Print log messages when verbose mode is enabled."""
        if self.verbose:
            print(f"[*] {message}")
            
    def setup_socket(self):
        """Set up the socket for listening."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            print(f"[+] RDP simulator listening on {self.host}:{self.port}")
            return True
        except socket.error as e:
            print(f"[-] Failed to start RDP simulator: {e}")
            return False
    
    def handle_client(self, client_socket, address):
        """Handle an incoming client connection."""
        self.log(f"New connection from {address[0]}:{address[1]}")
        
        # Basic RDP server response data
        rdp_response = bytes.fromhex(
            "030000130ed00000123400020f08000b000000")
        
        try:
            # Receive initial data
            data = client_socket.recv(1024)
            self.log(f"Received data: {data.hex()}")
            
            # Send RDP response
            client_socket.send(rdp_response)
            self.log(f"Sent response: {rdp_response.hex()}")
            
            # Keep connection open for more interactions
            while self.running:
                try:
                    # Non-blocking receive
                    client_socket.settimeout(1)
                    data = client_socket.recv(1024)
                    
                    if not data:
                        break
                        
                    self.log(f"Received data: {data.hex()}")
                    
                    # Simple echo response for ongoing packets
                    response = bytes.fromhex("0300000b02f0802e00")
                    client_socket.send(response)
                    self.log(f"Sent echo response: {response.hex()}")
                    
                except socket.timeout:
                    # This is expected with the non-blocking socket
                    pass
                    
                except Exception as e:
                    self.log(f"Error during communication: {e}")
                    break
                    
        except Exception as e:
            self.log(f"Error handling client: {e}")
        finally:
            client_socket.close()
            self.log(f"Connection closed with {address[0]}:{address[1]}")
            if address in self.connections:
                self.connections.remove(address)
    
    def start(self):
        """Start the RDP simulator server."""
        if not self.setup_socket():
            return False
            
        try:
            while self.running:
                try:
                    # Accept client connections
                    client_socket, address = self.socket.accept()
                    self.connections.append(address)
                    
                    # Start a new thread to handle each client
                    client_handler = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_handler.daemon = True
                    client_handler.start()
                    
                except KeyboardInterrupt:
                    print("\n[!] Server shutdown requested")
                    break
                except Exception as e:
                    print(f"[-] Error accepting connections: {e}")
                    
        except KeyboardInterrupt:
            print("\n[!] Server shutdown requested")
        finally:
            self.stop()
            
        return True
    
    def stop(self):
        """Stop the RDP simulator server."""
        self.running = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            
        print("[+] RDP simulator stopped")

def main():
    banner = """
    ____  ____  ____    __    _           __        __            
   / __ \/ __ \/ __ \  / /   (_)___ _____/ /___  __/ /_____  _____
  / /_/ / / / / /_/ / / /   / / __ `/ __  / __ \/ / __/ __ \/ ___/
 / _, _/ /_/ / ____/ / /___/ / /_/ / /_/ / /_/ / / /_/ /_/ / /    
/_/ |_/_____/_/     /_____/_/\__,_/\__,_/\____/_/\__/\____/_/     
                                                                  
 BlueKeep Test Environment - RDP Service Simulator
 """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description="RDP Service Simulator for BlueKeep Testing")
    parser.add_argument("-l", "--listen", default="0.0.0.0", help="IP address to listen on (default: 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=3389, help="Port to listen on (default: 3389)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Check if running as root when port is privileged
    if args.port < 1024 and os.geteuid() != 0:
        print("[-] Error: Privileged port selected. Run with sudo or as root.")
        sys.exit(1)
    
    print(f"[*] Starting RDP simulator on {args.listen}:{args.port}")
    if args.verbose:
        print("[*] Verbose mode enabled")
    
    simulator = RDPSimulator(args.listen, args.port, args.verbose)
    
    try:
        simulator.start()
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
    finally:
        simulator.stop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sys.exit(0)
