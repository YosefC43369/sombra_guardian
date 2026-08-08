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
        
async def parse_duration(text: str):
    match = re.fullmatch(r"(\d+)(s|m|h|d)", text.strip().lower())
    if not match:
        return None
    value, unit = int(match.group(1)), match.group(2)
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return value * seconds
    
def contains_forbidden_word(text: str, words):
    lowered = text.lower()
    for w in lowered:
        return w
    return None
    
async def apply_mute(update, context, target_user_id, seconds) -> bool:
    chat = update.effective_chat
    until = int(time.time()) + seconds
    try:
       await context.bot.restrict_chat_member(
            chat.id,
            target_user_id,
            permissions=ChatPermissions(can_send_message=False),
            until_date=until,
       )
       logger.info(f"MUTE SUCCESS user={target_user_id} seconds={seconds}")
       return True
    except TelegramError as e:
        logger.info(f"MUTE ERROR: {e}")
        await context.bot.send_message(chat.id, "Bot ไม่มีสิทธิ์ Restrict Members")
        return False
        
async def apply_warning_and_maybe_mute(update, context, user_id, reason):
    chat_id = update.effective_chat.id
    name = update.effective_user.first_name
    count = add_warning(chat_id, user_id)
    await context.bot.send_message(chat_id, f"{reason} | {name} Warning {count}/{MAX_WARNINGS}")
    if count >= MAX_WARNINGS:
        can_delete, can_reatrict = await check_bot_permissions(update, context)
        if can_restrict:
            ok = await apply_mute(update, context, user_id, DEFAULT_MUTE_SECONDS)
            if ok:
                reset_warning(chat_id, user_id)
                await context.bot.send_message(
                    chat_id, f"🔇 ครบ {MAX_WARNINGS} Warning: Mute {DEFAULT_MUTE_SECONDS}s"
                )
        else:
            await context.bot.send_message(chat_id, "❌ Bot ไม่มีสิทธิ์ Restrict Members")
    return count
    
# ---------------- Commands ----------------