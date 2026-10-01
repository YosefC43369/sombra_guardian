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
        r.write(token)
        
        
def load_encrypted(filename: str =  SCAN_RESULT_FILE) -> dict:
    with open(filename, "rb") as f:
        token = f.read()
        
    raw = fernet.decrypt(token)
    return json.loads(raw.decode("utf-8"))
    
    
def is_admin(message) -> bool:
    return message.from_user.id in ADMIN_IDS
    
    
@bot.message_handler(commands=["status"])
def status(message):
    if not is_admin(message):
        bot.reply_to(message, "Unauthorized.")
        return
        
    try:
        results = load_encrypted()
        summary = results.get("summary", {})
        bot.reply_to(message, json.dumps(summary, indent=2))
    except Exception:
        bot.reply_to(message, "Stored scan results are invalid or unreadable.")
        
        
@bot.message_handler(commands=["last_findings"])
def last_findings(message):
    if not is_admin(message):
        bot.reply_to(message, "Unauthorized.")
        return
        
    if not os.path.exists(SCAN_RESULT_FILE):
        bot.reply_to(message, "No encrypted scan results stored.")