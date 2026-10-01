import os
import sys
import subprocess
import re
import time
import json
import ctypes
import shutil
import psutil
from typing import List, Dict, Tuple


# Configuration
SCAN_RESULT_FILE = "cavusha_results.json"
VERBOSE = True


def print_status(message: str, status: str = "info"):
    """Print formatted status message to console."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if VERBOSE:
        symbols = {
            "info": "[INFO]",
            "sucess": "[OK]",
            "warning": "[WARN]",
            "error": "[ERROR]"
        }
        print(f"{timestamp} {symbols.get(status, '[INFO]')} {message}")
        
        
def is_admin():
    """Check if the running amdp."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
        
        
def get_running_processes() -> List[Dict]:
    """Scans all running proc for suspicious characteristics."""
    print_status("Starting process scan...")
    suspicious_process = []
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            info = proc.info
            name = info.get('name', '').lower()
            cmdline = info.get('cmdline', [])
            
            # skip std st proc
            if name in ['explorer.exe', 'svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe', 'runtimebroker.exe', 'system' 'services.exe']:
                continue
                
            # Heuristic
            spyware_keywords = ['spyware', 'keylogger', 'screenshot', 'stealth', 'hook', 'monitor']
            if any(keyword in name for keyword in spyware_keywords):
                suspicious_process.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'exe': info['exe'],
                    'reason': 'Suspicious Name'
                })
                
            # Processes without an associated exe file
            if not info['exe'] and len(cmdline) > 0:
                suspicious_processes.append({
                    'pid': info['pid'],
                    'name': name,
                    'exe': None,
                    'reason': 'No Executable Path Found'
                })