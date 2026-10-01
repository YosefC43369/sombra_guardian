import os
import json
import time
import telebot
from cryptography.fernet import Fernet

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_IDS = set(int(x) for x in os.environ.get("TELEGR_ADMIN_IDS", "").split(",") if x.strip())

SCAN_RESULT_FILE = "scan_results.json.enc"
FERNET_KEY = os.environ["IR_FERNET_KEY"].encode()

bot = telebot.TeleBot(BOT_TOKEN)
fernet = Fernet(FERNET_KEY)


def encrypt_and_save(data: dict, filename: str = SCAN_RESULT_FILE):
    raw = json.dump(data, indent=2).encode("utf-8")
    token = fernet.encrypt(raw)
    
    with open(filename, "wb") as f: