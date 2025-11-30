#!/usr/bin/env python3
"""
Encrypted P2P Chat Application
Supports both 1-on-1 and group encrypted messaging
"""

import socket
import threading
import json
import sys
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import time
from pathlib import Path


class EncryptedChat:
    def __init__(self, username, port, private_key=None):
        self.username = username
        self.port = port
        self.host = '0.0.0.0'
        self.peers = {}  # {peer_id: {'host': host, 'port': port, 'socket': socket}}
        self.cipher = None
        self.running = True
        self.server_socket = None
        self.user_id = hashlib.sha256(username.encode()).hexdigest()[:16]
        
        # Encryption setup
        if private_key:
            self.cipher = Fernet(private_key)
        else:
            self.cipher = Fernet(Fernet.generate_key())
        
        self.message_history = []
        self.lock = threading.Lock()
    
    def encrypt_message(self, message):
        """Encrypt a message using Fernet encryption"""
        if isinstance(message, str):
            message = message.encode()
        return self.cipher.encrypt(message).decode()
    
    def decrypt_message(self, encrypted_message):
        """Decrypt a message using Fernet encryption"""
        if isinstance(encrypted_message, str):
            encrypted_message = encrypted_message.encode()
        return self.cipher.decrypt(encrypted_message).decode()
    
    def start_server(self):
        """Start the P2P server to accept incoming connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[SERVER] Listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    threading.Thread(target=self.handle_incoming_connection, args=(conn, addr), daemon=True).start()
                except Exception as e:
                    if self.running:
                        print(f"[ERROR] Server error: {e}")
        except Exception as e:
            print(f"[ERROR] Failed to start server: {e}")
    
    def handle_incoming_connection(self, conn, addr):
        """Handle incoming connection from a peer"""
        try:
            # Receive peer info
            data = conn.recv(1024)
            peer_info = json.loads(self.decrypt_message(data.decode()))
            
            peer_id = peer_info.get('user_id')
            peer_username = peer_info.get('username')
            
            print(f"\n[CONNECTED] {peer_username} ({addr[0]}:{addr[1]})")
            
            # Store peer connection
            with self.lock:
                self.peers[peer_id] = {
                    'username': peer_username,
                    'host': addr[0],
                    'port': addr[1],
                    'socket': conn,
                    'last_seen': time.time()
                }
            
            # Listen for incoming messages
            while self.running:
                try:
                    message_data = conn.recv(4096)
                    if not message_data:
                        break
                    
                    message = json.loads(self.decrypt_message(message_data.decode()))
                    self.handle_message(message, peer_id)
                except Exception as e:
                    if self.running:
                        print(f"[ERROR] Error receiving message: {e}")
                    break
        
        except Exception as e:
            print(f"[ERROR] Connection error: {e}")
        finally:
            try:
                conn.close()
            except:
                pass
            with self.lock:
                if peer_id in self.peers:
                    del self.peers[peer_id]
                    print(f"[DISCONNECTED] Peer disconnected")
    
    def handle_message(self, message, sender_id):
        """Handle incoming message"""
        msg_type = message.get('type')
        content = message.get('content')
        timestamp = message.get('timestamp', datetime.now().isoformat())
        sender_name = message.get('sender')
        recipients = message.get('recipients', [])
        
        # Store in history
        with self.lock:
            self.message_history.append({
                'sender': sender_name,
                'content': content,
                'timestamp': timestamp,
                'type': msg_type,
                'recipients': recipients
            })
        
        if msg_type == 'direct':
            print(f"\n[{sender_name}]: {content}")
        elif msg_type == 'group':
            print(f"\n[GROUP][{sender_name}]: {content}")
        
        print(f"> ", end="", flush=True)
    
    def connect_to_peer(self, peer_host, peer_port):
        """Connect to another peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_host, peer_port))
            
            # Send our info
            peer_info = {
                'username': self.username,
                'user_id': self.user_id,
                'port': self.port
            }
            sock.send(self.encrypt_message(json.dumps(peer_info)).encode())
            
            print(f"[CONNECTED] Successfully connected to {peer_host}:{peer_port}")
            
            return sock
        except Exception as e:
            print(f"[ERROR] Failed to connect to {peer_host}:{peer_port}: {e}")
            return None
    
    def send_direct_message(self, recipient_id, message):
        """Send a direct message to a specific peer"""
        if recipient_id not in self.peers:
            print(f"[ERROR] Peer {recipient_id} not connected")
            return False
        
        try:
            msg_obj = {
                'type': 'direct',
                'sender': self.username,
                'sender_id': self.user_id,
                'content': message,
                'timestamp': datetime.now().isoformat(),
                'recipients': [recipient_id]
            }
            
            sock = self.peers[recipient_id]['socket']
            sock.send(self.encrypt_message(json.dumps(msg_obj)).encode())
            print(f"[SENT] Message sent to {self.peers[recipient_id]['username']}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
            return False
    
    def send_group_message(self, recipient_ids, message):
        """Send a group message to multiple peers"""
        if not recipient_ids:
            print("[ERROR] No recipients specified")
            return False
        
        success_count = 0
        for recipient_id in recipient_ids:
            if recipient_id not in self.peers:
                print(f"[WARNING] Peer {recipient_id} not connected")
                continue
            
            try:
                msg_obj = {
                    'type': 'group',
                    'sender': self.username,
                    'sender_id': self.user_id,
                    'content': message,
                    'timestamp': datetime.now().isoformat(),
                    'recipients': recipient_ids
                }
                
                sock = self.peers[recipient_id]['socket']
                sock.send(self.encrypt_message(json.dumps(msg_obj)).encode())
                success_count += 1
            except Exception as e:
                print(f"[ERROR] Failed to send to {recipient_id}: {e}")
        
        if success_count > 0:
            print(f"[SENT] Group message sent to {success_count} peer(s)")
            return True
        return False
    
    def list_peers(self):
        """List all connected peers"""
        if not self.peers:
            print("[INFO] No connected peers")
            return
        
        print("\n[CONNECTED PEERS]:")
        with self.lock:
            for peer_id, info in self.peers.items():
                print(f"  - {info['username']} ({info['host']}:{info['port']})")
                print(f"    ID: {peer_id}")
    
    def get_key(self):
        """Get the encryption key (for sharing with other peers)"""
        return self.cipher.key.decode()
    
    def interactive_mode(self):
        """Interactive command mode"""
        commands = {
            'help': 'Show this help message',
            'peers': 'List connected peers',
            'connect <host> <port>': 'Connect to a peer',
            'send <peer_id> <message>': 'Send direct message to a peer',
            'group <peer_ids_comma_separated> <message>': 'Send group message',
            'key': 'Show encryption key',
            'history': 'Show message history',
            'quit': 'Exit the application'
        }
        
        print(f"\n[USER] {self.username} (ID: {self.user_id})")
        print("[INFO] Type 'help' for available commands")
        
        while self.running:
            try:
                cmd = input("> ").strip()
                if not cmd:
                    continue
                
                parts = cmd.split(' ', 1)
                command = parts[0].lower()
                
                if command == 'help':
                    print("\n[COMMANDS]:")
                    for cmd_name, description in commands.items():
                        print(f"  {cmd_name}: {description}")
                
                elif command == 'peers':
                    self.list_peers()
                
                elif command == 'connect':
                    if len(parts) < 2:
                        print("[ERROR] Usage: connect <host> <port>")
                        continue
                    args = parts[1].split()
                    if len(args) < 2:
                        print("[ERROR] Usage: connect <host> <port>")
                        continue
                    host, port = args[0], int(args[1])
                    sock = self.connect_to_peer(host, port)
                    if sock:
                        # Create a thread to handle this connection
                        threading.Thread(target=self.handle_incoming_connection, 
                                       args=(sock, (host, port)), daemon=True).start()
                
                elif command == 'send':
                    if len(parts) < 2:
                        print("[ERROR] Usage: send <peer_id> <message>")
                        continue
                    args = parts[1].split(' ', 1)
                    if len(args) < 2:
                        print("[ERROR] Usage: send <peer_id> <message>")
                        continue
                    peer_id, message = args[0], args[1]
                    self.send_direct_message(peer_id, message)
                
                elif command == 'group':
                    if len(parts) < 2:
                        print("[ERROR] Usage: group <peer_ids_comma_separated> <message>")
                        continue
                    args = parts[1].split(' ', 1)
                    if len(args) < 2:
                        print("[ERROR] Usage: group <peer_ids_comma_separated> <message>")
                        continue
                    peer_ids = [p.strip() for p in args[0].split(',')]
                    message = args[1]
                    self.send_group_message(peer_ids, message)
                
                elif command == 'key':
                    print(f"[KEY] {self.get_key()}")
                
                elif command == 'history':
                    if not self.message_history:
                        print("[INFO] No message history")
                    else:
                        print("\n[MESSAGE HISTORY]:")
                        for msg in self.message_history[-10:]:
                            print(f"  [{msg['timestamp']}] {msg['sender']}: {msg['content']}")
                
                elif command == 'quit':
                    print("[INFO] Shutting down...")
                    self.running = False
                    break
                
                else:
                    print("[ERROR] Unknown command. Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print("\n[INFO] Shutting down...")
                self.running = False
                break
            except Exception as e:
                print(f"[ERROR] {e}")


def main():
    print("=" * 50)
    print("  ENCRYPTED P2P CHAT APPLICATION")
    print("=" * 50)
    
    username = input("Enter your username: ").strip()
    if not username:
        username = "User"
    
    try:
        port = int(input("Enter port to listen on (default 5000): ").strip() or "5000")
    except ValueError:
        port = 5000
    
    # Initialize chat
    chat = EncryptedChat(username, port)
    
    print(f"\n[INFO] Your User ID: {chat.user_id}")
    print(f"[INFO] Encryption Key: {chat.get_key()}")
    
    # Start server in background
    server_thread = threading.Thread(target=chat.start_server, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(0.5)
    
    # Start interactive mode
    chat.interactive_mode()
    
    # Cleanup
    if chat.server_socket:
        chat.server_socket.close()


if __name__ == "__main__":
    main()
