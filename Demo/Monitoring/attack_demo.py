import socket
import hmac
import hashlib
import os
import time
import threading
import random
import struct

# Server configuration
TCP_HOST = "127.0.0.1"
TCP_PORT = 1020

class ContinuousAttacker:
    def __init__(self):
        self.attack_count = 0
        self.running = True
        
    def generate_client_id(self):
        """Generate random client IDs"""
        prefixes = ['client', 'device', 'sensor', 'admin', 'user', 'test', 'node', 'iot']
        suffixes = ['1', '2', '3', '4', '5', 'admin', 'test', 'device', 'sensor']
        return random.choice(prefixes) + random.choice(suffixes) + str(random.randint(1, 1000))
    
    def attack_auth_bypass(self):
        """Continuous authentication bypass attempts"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((TCP_HOST, TCP_PORT))
                
                # Send client ID
                client_id = self.generate_client_id()
                sock.send(client_id.encode())
                print(f"[AUTH_BYPASS] Sent client ID: {client_id}")
                
                # Receive challenge
                challenge = sock.recv(1024)
                print(f"[AUTH_BYPASS] Received challenge: {challenge.hex()[:20]}...")
                
                # Send various malicious responses
                attacks = [
                    os.urandom(32),  # Random data
                    b'\x00' * 32,    # Null bytes
                    challenge,       # Echo challenge
                    b'A' * 32,       # Repeated bytes
                    hmac.digest(os.urandom(32), challenge, hashlib.sha256),  # Wrong key HMAC
                    b'\xff' * 32,    # All ones
                    challenge[:16] + b'\x00' * 16,  # Partial challenge
                ]
                
                for i, attack_response in enumerate(attacks):
                    try:
                        print(f"[AUTH_BYPASS] Sending attack response {i+1}")
                        sock.send(attack_response)
                        time.sleep(0.2)
                        
                        # Try to read any response
                        try:
                            response = sock.recv(1024)
                            if response:
                                print(f"[AUTH_BYPASS] Got response: {response.hex()[:20]}...")
                        except:
                            print("[AUTH_BYPASS] No response or connection closed")
                            break
                            
                    except Exception as e:
                        print(f"[AUTH_BYPASS] Send failed: {e}")
                        break
                
                sock.close()
                self.attack_count += 1
                print(f"[AUTH_BYPASS] Completed attack sequence #{self.attack_count}")
                
            except Exception as e:
                print(f"[AUTH_BYPASS] Connection failed: {e}")
            
            time.sleep(random.uniform(1, 3))
    
    def attack_protocol_abuse(self):
        """Continuous protocol abuse attacks"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((TCP_HOST, TCP_PORT))
                
                # Send malformed client IDs
                malformed_ids = [
                    b'A' * 5000,  # Very long ID
                    b'',          # Empty ID
                    b'\x00\x01\x02',  # Binary data
                    b'../../etc/passwd',  # Path traversal
                    b'<script>alert(1)</script>',  # XSS attempt
                    b'\x00' * 100,  # Null bytes
                    b'client' + b'\x00' * 50,  # Null padding
                ]
                
                for i, malicious_id in enumerate(malformed_ids):
                    try:
                        print(f"[PROTOCOL_ABUSE] Sending malformed ID {i+1}")
                        sock.send(malicious_id)
                        time.sleep(0.3)
                        
                        # Try to receive challenge even with bad ID
                        try:
                            challenge = sock.recv(1024)
                            if challenge:
                                print(f"[PROTOCOL_ABUSE] Got challenge: {challenge.hex()[:20]}...")
                                # Send random response
                                sock.send(os.urandom(32))
                        except:
                            print("[PROTOCOL_ABUSE] No challenge received")
                            
                    except Exception as e:
                        print(f"[PROTOCOL_ABUSE] Send failed: {e}")
                        break
                
                sock.close()
                self.attack_count += 1
                print(f"[PROTOCOL_ABUSE] Completed attack sequence #{self.attack_count}")
                
            except Exception as e:
                print(f"[PROTOCOL_ABUSE] Connection failed: {e}")
            
            time.sleep(random.uniform(2, 4))
    
    def attack_message_injection(self):
        """Continuous message injection attempts"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((TCP_HOST, TCP_PORT))
                
                # Send valid-looking client ID first
                client_id = "test_client_123"
                print(f"[MSG_INJECTION] Sending client ID: {client_id}")
                sock.send(client_id.encode())
                
                # Try to receive challenge but ignore it
                try:
                    challenge = sock.recv(1024)
                    print(f"[MSG_INJECTION] Received challenge, sending garbage response")
                    sock.send(os.urandom(32))  # Send garbage to pass to next stage
                except:
                    print("[MSG_INJECTION] No challenge received, proceeding anyway")
                
                # Send malformed message structures to try to crash the server
                injections = [
                    b'\x00' * 100,  # Null bytes
                    b'A' * 5000,    # Buffer overflow attempt
                    b'\xff\xff\xff\xff',  # Max length
                    os.urandom(100),  # Random data
                    struct.pack('>I', 0xFFFFFFFF) + b'A' * 100,  # Large length prefix
                    struct.pack('>I', 0) + b'A' * 100,  # Zero length prefix
                    b'\x00' * 12 + struct.pack('>I', 100) + b'A' * 50,  # Incomplete message
                ]
                
                for i, injection in enumerate(injections):
                    try:
                        print(f"[MSG_INJECTION] Sending injection {i+1}")
                        sock.send(injection)
                        time.sleep(0.2)
                    except Exception as e:
                        print(f"[MSG_INJECTION] Injection failed: {e}")
                        break
                
                sock.close()
                self.attack_count += 1
                print(f"[MSG_INJECTION] Completed attack sequence #{self.attack_count}")
                
            except Exception as e:
                print(f"[MSG_INJECTION] Connection failed: {e}")
            
            time.sleep(random.uniform(1.5, 3.5))
    
    def attack_rapid_connections(self):
        """Rapid connection attempts to stress the server"""
        while self.running:
            connections = []
            print("[RAPID_CONNECT] Starting rapid connection burst")
            
            for i in range(10):  # Try to make multiple rapid connections
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((TCP_HOST, TCP_PORT))
                    
                    # Send quick client ID and close
                    sock.send(f"rapid_client_{i}".encode())
                    connections.append(sock)
                    print(f"[RAPID_CONNECT] Connection {i+1} established")
                    
                except Exception as e:
                    print(f"[RAPID_CONNECT] Connection {i+1} failed: {e}")
            
            # Close all connections
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
            
            self.attack_count += 1
            print(f"[RAPID_CONNECT] Completed burst #{self.attack_count}")
            time.sleep(random.uniform(3, 6))
    
    def attack_slowloris(self):
        """Slowloris-style attack with partial connections"""
        while self.running:
            try:
                socks = []
                print("[SLOWLORIS] Starting slow connection attack")
                
                # Create multiple partial connections
                for i in range(5):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(10)
                        sock.connect((TCP_HOST, TCP_PORT))
                        
                        # Send partial client ID
                        partial_id = f"slow_client_{i}"
                        sock.send(partial_id.encode()[:5])  # Send only part of ID
                        socks.append(sock)
                        print(f"[SLOWLORIS] Partial connection {i+1} established")
                        
                    except Exception as e:
                        print(f"[SLOWLORIS] Partial connection {i+1} failed: {e}")
                
                # Keep connections open for a while
                print("[SLOWLORIS] Holding connections open...")
                time.sleep(10)
                
                # Try to complete the connections
                for i, sock in enumerate(socks):
                    try:
                        # Send the rest of the client ID
                        sock.send(f"slow_client_{i}"[5:].encode())
                        time.sleep(1)
                    except:
                        pass
                
                # Close all connections
                for sock in socks:
                    try:
                        sock.close()
                    except:
                        pass
                
                self.attack_count += 1
                print(f"[SLOWLORIS] Completed attack #{self.attack_count}")
                
            except Exception as e:
                print(f"[SLOWLORIS] Attack failed: {e}")
            
            time.sleep(random.uniform(5, 10))
    
    def start_all_attacks(self):
        """Start all attack threads"""
        print("Starting continuous TCP attack simulation...")
        print(f"Target: {TCP_HOST}:{TCP_PORT}")
        print("Press Ctrl+C to stop attacks\n")
        
        attacks = [
            self.attack_auth_bypass,
            self.attack_protocol_abuse,
            self.attack_message_injection,
            self.attack_rapid_connections,
            self.attack_slowloris,
        ]
        
        for attack in attacks:
            thread = threading.Thread(target=attack)
            thread.daemon = True
            thread.start()
    
    def stop_attacks(self):
        """Stop all attacks"""
        self.running = False
    
    def get_stats(self):
        """Return attack statistics"""
        return {
            "total_attacks": self.attack_count,
            "running": self.running
        }

def main():
    attacker = ContinuousAttacker()
    
    try:
        attacker.start_all_attacks()
        
        # Keep main thread alive and print stats periodically
        while True:
            stats = attacker.get_stats()
            print(f"\n=== Attack Statistics ===")
            print(f"Total attack sequences: {stats['total_attacks']}")
            print(f"Status: {'RUNNING' if stats['running'] else 'STOPPED'}")
            print("=" * 25)
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\nStopping attacks...")
        attacker.stop_attacks()
        time.sleep(2)
        print("All attacks stopped.")

if __name__ == "__main__":
    main()