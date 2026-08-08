import os
import re
import time
import sqlite3
import logging
from collections import defaultdict, deque

from dotenv import load_dotenv
from telegram import Update, ChatPermissions
from telegram.constants import ChatMemberStatus
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.error import TelegramError

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
DB_PATH = "bot.db"

SPAM_MESSAGE_LIMIT = 5
SPAM_TIME_WINDOW = 10
MAX_WARNINGS = 3
DEFAULT_MUTE_SECONDS = 600

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("modbot")

spam_tracker = defaultdict(deque)

# ---------------- Database ----------------

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
def db_info():
    conn = db_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS forbidden_words (
        chat_id INTEGER NOT NULL,
        word TEXT NOT NULL,
        PRIMARY KEY (chat_id, word)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS warnings (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS settings (
        chat_id INTEGER PRIMARY KEY,
        filter_on INTEGER NOT NULL DEFAULT 1,
        antispam_on INTEGER NOT NULL DEFAULT 1
    )""")
    conn.commit()
    conn.close()
    
def get_settings(chat_id):
    conn = db_conn()
    conn.execute(
        "INSERT OR IGNORE INTO settings (chat_id, filter_on, antispam_on) VALUES (?, 1, 1)",
        (chat_id,),
    )
    conn.commit()
    row = conn.execute(
        "SELECT filter_on, antispam_on FROM settings WHERE chat_id=?", (chat_id,)
    ).fetchone()
    conn.close()
    return {"filter_on": row["filter_on"], "antispam_on": row["antispam_on"]}
    
def set_filter(chat_id, word):
    conn = db_conn()
    conn.execute(
        "INSERT OR IGNORE INTO forbidden_words (chat_id, word) VALUES (?, ?)",
        (chat_id, word.lower()),
    )
    conn.commit()
    conn.close()
    
def add_word(chat_id, word):
    conn = db_conn()
    conn.execute(
        "INSERT OR IGNORE INTO forbidden_words (chat_id, word) VALUES (?, ?)",
        (chat_id, word.lower()),
    )
    conn.commit()
    conn.close()
    
def del_word(chat_id, word):
    conn = db_conn()
    conn.execute("DELETE FROM forbidden_words WHERE chat_id=? AND word=?", (chat_id, word.lower()))
    conn.commit()
    conn.close()
    
def list_words(chat_id):
    conn = db_conn()
    rows = conn.execute("SELECT word FROM forbidden_words WHERE chat_id=?", (chat_id,)).fetchall()
    conn.close()
    return [r["word"] for r in rows]
    
def get_warning(chat_id, user_id):
    conn = db_conn()
    row = conn.exexute(
        "SELECT count FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id)
    ).fetchone()
    conn.close()
    return row["count"] if row else 0
    
def add_warning(chat_id, user_id):
    conn = db_conn()
    conn.execute(
        "INSERT INTO warnings (chat_id, user_id, count) VALUES (?, ?, 1) "
        "ON CONFLICT(chat_id, user_id) DO UPDATE SET count = count + 1",
        (chat_id, user_id),
    )
    conn.commit()
    row = conn.execute(
        "SELECT count FROM warnings WHERE chat_id=? AND user_id=?", (chat_id, user_id)
    ).fetchone()
    conn.close()
    return row["count"]
    
def reset_warning(chat_id, user_id):
    conn = db_conn()
    conn.execute(
        "INSERT OR REPLACE INTO warnings (chat_id, user_id, count) VALUES (?, ?, 0)",
        (chat_id, user_id),
    )
    conn.commit()
    conn.close()
    
# ---------------- Helpers ----------------

async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    chat = update.effective_chat
    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
        return member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)
    except TelegramError as e:
        logger.info(f"ADMIN CHECK ERROR: {e}")
        return False
        
async def check_bot_permissions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    try:
        me = await context.bot.get_chat_member(chat.id, context.bot.id)
        can_delete = bool(getattr(me, "can_delete_messages", False))
        can_restrict = bool(getattr(me, "can_restrict_members", False))
        return can_delete, can_restrict
    except TelegramError as e:
        logger.info(f"PERMISSION CHECK ERROR: {e}")
        return False, False