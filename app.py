import os
import re
import time
import sqlite3
import logging
import asyncio
from collections import defaultdict, deque

from dotenv import load_dotenv
load_dotenv()

from telegram import Update, ChatPermissions
from telegram.constants import ChatMemberStatus, ChatAction, ChatType
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.error import TelegramError

import detection
from security import security_db_init, write_audit_log
import gemini
from gemini import ask_gemini, split_telegram_message
from quota import quota_db_init, check_and_use_quota
from analytics import analytics_db_init, record_message_activity, get_group_summary
from news import news_db_init, run_news_check_cycle, news_background_loop
from scope_policy import (
    scope_policy_db_init,
    ProgramStatus,
    create_program,
    get_program,
    list_programs,
    set_program_status,
    import_authorization,
    get_authorization,
    list_authorizations,
    review_authorization,
    revoke_authorization,
    add_scope_rule,
    remove_scope_rule,
    list_scope_rules,
    evaluate_target,
    VALID_RULE_TYPES,
    VALID_TARGET_TYPES,
)

import coordinator

from dashboard import get_dashboard_data, format_dashboard_message
from security import write_audit_log
from telegram.constants import ParseMode

BOT_TOKEN = os.getenv("BOT_TOKEN")
DB_PATH = "bot.db"

SPAM_MESSAGE_LIMIT = 5
SPAM_TIME_WINDOW = 10
MAX_WARNINGS = 3
DEFAULT_MUTE_SECONDS = 600
TELEGRAM_CAPTION_LIMIT = 1024  # Telegram Bot API: caption max length for send_photo

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("modbot")

spam_tracker = defaultdict(deque)

AUTO_REPLY_TRIGGERS = {
    "ควย": "ควยพ่อมึงอะ ไอ้ควาย",
    "ควยไรอะ": "แล้วมึงเป็นควยไรอะ",
    "ต่อยกับกูไหม": "มาดิ ไอ้ควาย อย่าท้า",
    "ฝอ.3": "ไอ้หม่ำหรอ กูให้ 3 ไอ้หม่ำเลย",
}
AUTO_REPLY_ANNOY_THRESHOLD = 3
AUTO_REPLY_ANGRY_THRESHOLD = 5
AUTO_REPLY_ANNOYED_TEXT = "มึงพิมพ์เหี้ยไรนักหนาวะ ว่างมากก็ไปกรอกน้ำให้แม่มึงไป ไอ้สัตว์นรก"
AUTO_REPLY_ANGRY_TEXT = "ยัง ยังไม่หยุดอีก กูรำคาญ ไอ้ควาย เดี๋ยวสะง่องหรอก"

DEFAULT_MEDIA_QUESTION = "ช่วยวิเคราะห์ไฟล์/รูปภาพที่แนบมาให้หน่อย อธิบายเป็นภาษาไทยอย่างละเอียด"

auto_reply_tracker = defaultdict(int)

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
    
def set_filter_on(chat_id, enabled):
    conn = db_conn()
    conn.execute(
        "INSERT INTO settings (chat_id, filter_on) VALUES (?, ?) "
        "ON CONFLICT(chat_id) DO UPDATE SET filter_on = excluded.filter_on",
        (chat_id, int(enabled)),
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
    row = conn.execute(
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
        
def _find_bot_mention(entities: dict, bot_username: str):
    """entities is the dict returned by Message.parse_entities()/
    parse_caption_entities() — {MessageEntity: substring}. Returns the
    matched '@username' substring, or None."""
    target = f"@{bot_username.lower()}"
    for entity_text in entities.values():
        if entity_text.lower() == target:
            return entity_text
    return None
    
async def extract_media_from_message(message, context: ContextTypes.DEFAULT_TYPE):
    """ดาวน์โหลดรูปภาพ/เอกสารจาก Telegram message เพื่อส่งให้ GPT วิเคราะห์
    คืนค่า (bytes, mime_type, error_text):
      - ไม่มีรูป/เอกสารแนบเลย         -> (None, None, None)
      - มีแนบแต่ชนิดไฟล์ไม่รองรับ/ใหญ่เกิน -> (None, None, <ข้อความ error ภาษาไทย>)
      - ดาวน์โหลดสำเร็จ               -> (bytes, mime_type, None)
    ไม่เคยตัดข้อความ/ไฟล์ทิ้งเงียบๆ — ทุก error path คืนข้อความอธิบายกลับไปเสมอ"""
    file_id, mime_type, file_size = None, None, None
    
    if message.photo:
        largest = message.photo[-1]
        file_id, mime_type, file_size = largest.file_id, "image/jpeg", largest.file_size
    elif message.document:
        doc = message.document
        file_id, mime_type, file_size = doc.file_id, doc.mime_type or "", doc.file_size
        
    if not file_id:
        return None, None, None

    if not gemini.is_supported_media_mime(mime_type):
        return None, None, (
            f"❌ ไม่รองรับไฟล์ประเภทนี้ ({mime_type or 'ไม่ทราบชนิด'})\n"
            "รองรับ: รูปภาพ (JPEG/PNG/WebP), PDF, ไฟล์ข้อความล้วน (.txt)"
        )
        
    limit_mb = gemini.MAX_MEDIA_BYTES // (1024 * 1024)
    if file_size and file_size > gemini.MAX_MEDIA_BYTES:
        return None, None, f"❌ ไฟล์ใหญ่เกินไป (จำกัด {limit_mb}MB)"
        
    try:
        tg_file = await context.bot.get_file(file_id)
        file_bytes = bytes(await tg_file.download_as_bytearray())
    except TelegramError as e:
        logger.info(f"MEDIA DOWNLOAD ERROR: {e}")
        return None, None, "❌ ดาวน์โหลดไฟล์จาก Telegram ไม่สำเร็จ ลองใหม่อีกครั้ง"
        
    if len(file_bytes) > gemini.MAX_MEDIA_BYTES:
        return None, None, f"❌ ไฟล์ใหญ่เกินไป (จำกัด {limit_mb}MB)"
        
    return file_bytes, mime_type, None
        
async def parse_duration(text: str):
    match = re.fullmatch(r"(\d+)(s|m|h|d)", text.strip().lower())
    if not match:
        return None
    value, unit = int(match.group(1)), match.group(2)
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return value * seconds
    
def contains_forbidden_word(text: str, words):
    lowered = text.lower()
    for w in words:
        if w in lowered:
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
        
async def safe_delete(message, chat_id, context) -> bool:
    try:
        await context.bot.delete_message(chat_id, message.message_id)
        logger.info(f"MESSAGE DELETED | Chat ID: {chat_id} | Message ID: {message.message_id}")
        return True
    except TelegramError as e:
        logger.info(f"DELETE ERROR: {e}")
        return False
        
async def apply_warning_and_maybe_mute(update, context, user_id, reason):
    chat_id = update.effective_chat.id
    name = update.effective_user.first_name
    count = add_warning(chat_id, user_id)
    await context.bot.send_message(chat_id, f"{reason} | {name} Warning {count}/{MAX_WARNINGS}")
    if count >= MAX_WARNINGS:
        can_delete, can_restrict = await check_bot_permissions(update, context)
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

async def cmd_start(update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🤖 กูมาเพื่อช่วยเหลือพวกมึงแล้ว พวกเดนนรก\nพิมพ์ /help เพื่อดูคำสั่งทั้งหมด พัฒนาโดย @wissha_yosef พ่อกูเอง")
    
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "/status - ดูสถานะบอท\n"
        "/filter_on /filter_off - เปิด/ปิดตัวกรองคำ\n"
        "/addword <คำ> - เพิ่มคำต้องห้าม\n"
        "/delword <คำ> - ลบคำต้องห้าม\n"
        "/listwords - แสดงคำต้องห้ามทั้งหมด\n"
        "/warnings - ดู Warning (Reply ข้อความ)\n"
        "/resetwarn - รีเซ็ต Warning (Reply ข้อความ)\n"
        "/mute 10m - Mute สมาชิก (Reply ข้อความ)\n"
        "/unmute - ปลด Mute (Reply ข้อความ)\n"
        "/id - ดู Chat ID\n"
        f"แท็ก @{context.bot.username} แล้วพิมพ์คำถาม - ถาม AI\n"
        f"ส่งรูปภาพ/ไฟล์ PDF/TXT พร้อม caption แท็ก @{context.bot.username} "
        f"(หรือ Reply รูป/ไฟล์เดิมแล้วแท็ก) - ให้ AI วิเคราะห์รูป/ไฟล์\n"
        "/imagine <คำอธิบาย> - ให้ AI สร้างรูปภาพแล้วส่งเข้าแชท"
    )
    await update.message.reply_text(text)
    
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    settings = get_settings(chat_id)
    words_count = len(list_words(chat_id))
    can_delete, can_restrict = await check_bot_permissions(update, context)
    text = (
        f"Filter: {'ON' if settings['filter_on'] else 'OFF'}\n"
        f"Anti-Spam: {'ON' if settings['antispam_on'] else 'OFF'}\n"
        f"Forbidden Words: {words_count}\n"
        f"Bot Delete Permission: {'OK' if can_delete else 'MISSING'}\n"
        f"Bot Restrict Permission: {'OK' if can_restrict else 'MISSING'}"
    )
    await update.message.reply_text(text)
    
async def cmd_filter_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    set_filter_on(update.effective_chat.id, True)
    await update.message.reply_text("✅ เปิด Filter แล้ว")
    
async def cmd_filter_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    set_filter_on(update.effective_chat.id, False)
    await update.message.reply_text("✅ ปิด Filter แล้ว")
    
async def cmd_addword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /addword คำ")
    word = " ".join(context.args)
    add_word(update.effective_chat.id, word)
    await update.message.reply_text(f"✅ เพิ่มคำต้องห้าม: {word}")
    
async def cmd_delword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /delword คำ")
    word = " ".join(context.args)
    del_word(update.effective_chat.id, word)
    await update.message.reply_text(f"✅ ลบคำต้องห้าม: {word}")

async def cmd_listwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    words = list_words(update.effective_chat.id)
    if not words:
        return await update.message.reply_text("ยังไม่มีคำต้องห้าม")
    await update.message.reply_text("คำต้องห้าม:\n" + "\n".join(words))

async def cmd_warnings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /warnings")
    target = update.message.reply_to_message.from_user
    count = get_warning(update.effective_chat.id, target.id)
    await update.message.reply_text(f"{target.first_name}: Warning {count}/{MAX_WARNINGS}")

async def cmd_resetwarn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /resetwarn")
    target = update.message.reply_to_message.from_user
    reset_warning(update.effective_chat.id, target.id)
    await update.message.reply_text(f"✅ รีเซ็ต Warning ของ {target.first_name} แล้ว")

async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /mute 10m")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /mute 10m (รองรับ s, m, h, d)")
    seconds = await parse_duration(context.args[0])
    if seconds is None:
        return await update.message.reply_text("รูปแบบเวลาไม่ถูกต้อง เช่น 10s 10m 1h 1d")
    can_delete, can_restrict = await check_bot_permissions(update, context)
    if not can_restrict:
        return await update.message.reply_text("❌ Bot ไม่มีสิทธิ์ Restrict Members")
    target = update.message.reply_to_message.from_user
    ok = await apply_mute(update, context, target.id, seconds)
    if ok:
        await update.message.reply_text(f"🔇 Mute {target.first_name} เป็นเวลา {context.args[0]}")

async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not update.message.reply_to_message:
        return await update.message.reply_text("ใช้งาน: Reply ข้อความสมาชิกแล้วพิมพ์ /unmute")
    target = update.message.reply_to_message.from_user
    chat = update.effective_chat
    try:
        chat_info = await context.bot.get_chat(chat.id)
        permissions = chat_info.permissions or ChatPermissions(can_send_messages=True)
        await context.bot.restrict_chat_member(chat.id, target.id, permissions=permissions)
        await update.message.reply_text(f"🔊 ปลด Mute {target.first_name} แล้ว")
        logger.info(f"UNMUTE SUCCESS user={target.id}")
    except TelegramError as e:
        logger.info(f"UNMUTE ERROR: {e}")
        await update.message.reply_text("❌ Bot ไม่มีสิทธิ์ Restrict Members")
        
async def cmd_announce(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """ส่งข้อความประกาศเข้ากลุ่ม สั่งได้เฉพาะในแชทส่วนตัวกับบอทเท่านั้น

    ใช้งาน:
      1) ข้อความอย่างเดียว:
         /announce <chat_id> <ข้อความ>

      2) รูปภาพ + ข้อความ:
         ส่งรูปภาพเข้าแชทส่วนตัวกับบอท (จะใส่ caption หรือไม่ก็ได้)
         แล้ว Reply รูปภาพนั้นด้วย /announce <chat_id> [ข้อความ]
         - ถ้าไม่พิมพ์ข้อความต่อท้าย chat_id จะใช้ caption ของรูปเป็นข้อความประกาศ
         - ถ้าพิมพ์ข้อความต่อท้าย chat_id ข้อความนั้นจะ override caption เดิม

    ผู้สั่งต้องเป็น Admin/Owner ของกลุ่มที่ระบุ chat_id นั้น"""
    if update.effective_chat.type != ChatType.PRIVATE:
        return await update.message.reply_text("คำสั่งนี้ใช้ได้เฉพาะในแชทส่วนตัวกับบอทเท่านั้น")

    reply_msg = update.message.reply_to_message
    is_photo_announce = bool(reply_msg and reply_msg.photo)

    if not context.args:
        return await update.message.reply_text(
            "ใช้งาน:\n"
            "1) /announce <chat_id> <ข้อความ>\n"
            "2) ส่งรูปภาพ (ใส่ caption ได้) แล้ว Reply รูปนั้นด้วย /announce <chat_id> [ข้อความ]\n"
            "ดู chat_id ของกลุ่มได้จาก /status ในกลุ่มนั้น"
        )

    try:
        target_chat_id = int(context.args[0])
    except ValueError:
        return await update.message.reply_text("chat_id ต้องเป็นตัวเลข")

    typed_text = " ".join(context.args[1:]).strip()

    if is_photo_announce:
        announce_text = typed_text or (reply_msg.caption or "").strip()
        if not announce_text:
            return await update.message.reply_text(
                "❌ ไม่มีข้อความประกาศ กรุณาใส่ caption ให้รูป หรือพิมพ์ข้อความต่อท้าย chat_id"
            )
        photo_file_id = reply_msg.photo[-1].file_id
    else:
        if len(context.args) < 2:
            return await update.message.reply_text(
                "ใช้งาน: /announce <chat_id> <ข้อความ>\nดู chat_id ของกลุ่มได้จาก /status ในกลุ่มนั้น"
            )
        announce_text = typed_text
        if not announce_text:
            return await update.message.reply_text("กรุณาพิมพ์ข้อความที่ต้องการประกาศต่อท้าย chat_id")

    user = update.effective_user
    try:
        member = await context.bot.get_chat_member(target_chat_id, user.id)
    except TelegramError as e:
        logger.info(f"ANNOUNCE ADMIN CHECK ERROR: {e}")
        return await update.message.reply_text("❌ ไม่พบกลุ่มนี้ หรือบอตไม่ได้อยู่ในกลุ่มนั้น")

    if member.status not in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin ของกลุ่มที่ระบุ")

    full_text = f"📢 ประกาศ\n\n{announce_text}"

    if is_photo_announce:
        if len(full_text) > TELEGRAM_CAPTION_LIMIT:
            return await update.message.reply_text(
                f"❌ ข้อความประกาศยาวเกินไปสำหรับ caption ของรูปภาพ "
                f"({len(full_text)}/{TELEGRAM_CAPTION_LIMIT} ตัวอักษร)\n"
                f"กรุณาย่อข้อความ หรือส่งแบบข้อความอย่างเดียวแทน"
            )
        try:
            await context.bot.send_photo(target_chat_id, photo=photo_file_id, caption=full_text)
        except TelegramError as e:
            logger.info(f"ANNOUNCE PHOTO SEND ERROR: {e}")
            return await update.message.reply_text(
                "❌ ส่งรูปภาพไม่สำเร็จ บอทอาจไม่มีสิทธิ์พูดในกลุ่มนั้น หรือรูปภาพมีปัญหา"
            )
        write_audit_log(target_chat_id, user.id, actor="admin", action="ANNOUNCE_PHOTO", detail=announce_text)
        logger.info(f"ANNOUNCE PHOTO SENT | Chat ID: {target_chat_id} | By User ID: {user.id}")
    else:
        try:
            await context.bot.send_message(target_chat_id, full_text)
        except TelegramError as e:
            logger.info(f"ANNOUNCE SEND ERROR: {e}")
            return await update.message.reply_text("❌ ส่งข้อความไม่สำเร็จ บอทอาจไม่มีสิทธิ์พูดในกลุ่มนั้น")
        write_audit_log(target_chat_id, user.id, actor="admin", action="ANNOUNCE_TEXT", detail=announce_text)
        logger.info(f"ANNOUNCE TEXT SENT | Chat ID: {target_chat_id} | By User ID: {user.id}")

    await update.message.reply_text("✅ ส่งประกาศเรียบร้อยแล้ว")

IMAGINE_CAPTION_RE = re.compile(r"^/imagine(@\w+)?\s*", re.IGNORECASE)

async def _run_imagine(update: Update, context: ContextTypes.DEFAULT_TYPE, prompt: str, image_message) -> None:
    """สร้าง/แก้ไขรูปภาพด้วย AI แล้วส่งเข้าแชท ใช้ร่วมกันทั้ง 3 ทาง:
    /imagine <ข้อความ> ธรรมดา (สร้างใหม่ไม่มีรูปอ้างอิง), Reply รูปเดิมด้วย
    /imagine (แก้ไขรูปนั้น), และส่งรูปใหม่พร้อม caption /imagine (แก้ไขรูปที่เพิ่งส่ง)
    image_message คือ message ที่คาดว่าจะมีรูป/เอกสารแนบ (หรือ None ถ้าไม่มี)"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    if not prompt:
        return await update.message.reply_text(
            "ใช้งาน: /imagine <คำอธิบายรูปที่ต้องการ>\n"
            "เช่น /imagine แมวส้มใส่หมวกนักบินอวกาศ สไตล์การ์ตูน\n"
            "หรือ Reply รูป/ส่งรูปพร้อม caption /imagine <สิ่งที่ต้องการแก้ไข> เพื่อแก้ไขรูปเดิม"
        )

    image_bytes, image_mime, media_error = None, None, None
    if image_message and (image_message.photo or image_message.document):
        image_bytes, image_mime, media_error = await extract_media_from_message(image_message, context)
        if media_error:
            return await update.message.reply_text(media_error)
        if image_bytes and not image_mime.startswith("image/"):
            return await update.message.reply_text("❌ แก้ไขรูปได้เฉพาะไฟล์รูปภาพเท่านั้น (JPEG/PNG/WebP)")

    admin = await is_admin(update, context)
    allowed, used, limit = check_and_use_quota(chat_id, user_id, admin)
    if not allowed:
        return await update.message.reply_text(
            f"ใช้งานเกินโควตาวันนี้แล้ว ({used}/{limit} ครั้ง) ไว้มาใช้วันอื่นนะ หรือถ้ารีบก็ไปใช้งานบนเว็บไป ไอ้ควาย ไม่ต้องมาใช้กู นอกจากจะเปลือง Token แล้วยังเปลืองออกซิเจนเพราะมึงแย่งหายใจอีก🖕🏻"
        )

    mode = "edit" if image_bytes else "generate"
    logger.info(f"AI IMAGINE | Chat ID: {chat_id} | User ID: {user_id} | Mode: {mode} | Prompt: {prompt}")
    await context.bot.send_chat_action(chat_id, ChatAction.UPLOAD_PHOTO)

    if image_bytes:
        ok, result_bytes, error_text = await gemini.edit_image(prompt, image_bytes, image_mime)
        action_tag = "AI_IMAGE_EDITED"
    else:
        ok, result_bytes, error_text = await gemini.generate_image(prompt)
        action_tag = "AI_IMAGE_GENERATED"

    if not ok:
        return await update.message.reply_text(f"❌ {error_text}")

    caption = f"🎨 {prompt}"
    if len(caption) > TELEGRAM_CAPTION_LIMIT:
        caption = caption[: TELEGRAM_CAPTION_LIMIT - 1] + "…"

    try:
        await context.bot.send_photo(chat_id, photo=result_bytes, caption=caption)
    except TelegramError as e:
        logger.info(f"IMAGINE SEND ERROR: {e}")
        return await update.message.reply_text("❌ สร้างรูปสำเร็จแต่ส่งรูปเข้าแชทไม่สำเร็จ ลองใหม่อีกครั้ง")

    write_audit_log(chat_id, user_id, actor="user", action=action_tag, detail=prompt)


async def cmd_imagine(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """สั่ง AI สร้าง/แก้ไขรูปภาพแล้วส่งเข้าแชทนี้
    ใช้งาน: /imagine <คำอธิบาย> (สร้างรูปใหม่)
    หรือ Reply รูปเดิมด้วย /imagine <สิ่งที่ต้องการแก้ไข> (แก้ไขรูป)"""
    prompt = " ".join(context.args).strip()
    await _run_imagine(update, context, prompt, update.message.reply_to_message)


async def handle_imagine_caption(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """ส่งรูปพร้อม caption '/imagine <ข้อความ>' ในข้อความเดียว — แก้ไขรูปที่แนบมานั้น
    (คำสั่งใน caption ไม่ถูก CommandHandler จับ เพราะ CommandHandler อ่านจาก
    message.text เท่านั้น จึงต้องมี handler แยกที่จับจาก caption โดยตรง)"""
    message = update.effective_message
    prompt = IMAGINE_CAPTION_RE.sub("", message.caption or "", count=1).strip()
    await _run_imagine(update, context, prompt, message)
    
async def dashboard_command(update, context):
    chat, user = update.effective_chat, update.effective_user
    member = await context.bot.get_chat_member(chat.id, user.id)
    if member.status not in ("administrator", "creator"):
        await update.message.reply_text("คำสั่งนี้ใช้ได้เฉพาะแอดมินกลุ่มเท่านั้น")
        return
    text = format_dashboard_message(get_dashboard_data(chat.id, hours=24))
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    write_audit_log(chat.id, user.id, actor="admin", action="DASHBOARD_VIEW")
    
async def cmd_personal_identity(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Authorized Personal Identity / PII exposure analysis."""
    if not await is_admin(update, context):
        return await update.message.reply_text(
            "❌ Personal Identity Investigation ใช้ได้เฉพาะ Admin"
        )

    question = " ".join(context.args).strip()
    if not question:
        return await update.message.reply_text(
            "ใช้งาน: /identity <authorized OSINT/security investigation>"
        )

    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    allowed, used, limit = check_and_use_quota(chat_id, user_id, True)
    if not allowed:
        return await update.message.reply_text(
            f"ใช้งานเกินโควตาวันนี้แล้ว ({used}/{limit} ครั้ง)"
        )

    write_audit_log(
        chat_id,
        user_id,
        actor="admin",
        action="PERSONAL_IDENTITY_ANALYSIS",
        detail=question[:500],
    )

    await context.bot.send_chat_action(chat_id, ChatAction.TYPING)

    ok, result = await coordinator.handle_request(
        chat_id=chat_id,
        user_id=user_id,
        is_admin=True,
        question=question,
        preset="personal_identity",
    )

    if not ok:
        return

    for chunk in split_telegram_message(result):
        await update.message.reply_text(chunk)
        
async def cmd_corporate_espionage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Authorized defensive Corporate Intelligence / leak analysis."""
    if not await is_admin(update, context):
        return await update.message.reply_text(
            "❌ Corporate Espionage Investigation ใช้ได้เฉพาะ Admin"
        )

    question = " ".join(context.args).strip()
    if not question:
        return await update.message.reply_text(
            "ใช้งาน: /corporate <authorized defensive corporate investigation>"
        )

    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    allowed, used, limit = check_and_use_quota(chat_id, user_id, True)
    if not allowed:
        return await update.message.reply_text(
            f"ใช้งานเกินโควตาวันนี้แล้ว ({used}/{limit} ครั้ง)"
        )

    write_audit_log(
        chat_id,
        user_id,
        actor="admin",
        action="CORPORATE_ESPIONAGE_ANALYSIS",
        detail=question[:500],
    )

    await context.bot.send_chat_action(chat_id, ChatAction.TYPING)
    
    ok, result = await coordinator.handle_request(
        chat_id=chat_id,
        user_id=user_id,
        is_admin=True,
        question=question,
        preset="corporate_espionage",
    )

    if not ok:
        return
        
    for chunk in split_telegram_message(result):
        await update.message.reply_text(chunk)
    
async def chat_id_command(update, context):
    thread_id = update.effective_message.message_thread_id
    text = f"Chat ID: `{update.effective_chat.id}`"
    if thread_id:
        text += f"\nTopic (Thread) ID: `{thread_id}`"
    await update.message.reply_text(text, parse_mode="Markdown")
    
# ---------------- Anti-Link Commands ----------------

async def cmd_linkfilter_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    detection.enable_link_filter(update.effective_chat.id)
    await update.message.reply_text("✅ เปิด Link Filter แล้ว")
    
async def cmd_link_filter_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    detection.disable_link_filter(update.effective_chat.id)
    await update.message.reply_text("✅ ปิด Link Filter แล้ว")
    
async def cmd_adddomain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /adddomain example.com")
    domain = context.args[0]
    detection.add_domain(update.effective_chat.id, domain)
    await update.message.reply_text(f"✅ เพิ่ม Blocked Domain: {domain}")
    
async def cmd_deldomain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    if not context.args:
        return await update.message.reply_text("ใช้งาน: /deldomain example.com")
    domain = context.args[0]
    removed = detection.remove_domain(update.effective_chat.id, domain)
    if removed:
        await update.message.reply_text(f"✅ ลบ Blocked Domain: {domain}")
    else:
        await update.message.reply_text(f"ไม่พบ Domain นี้ในรายการ: {domain}")
        
async def cmd_listdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    domains = detection.get_blocked_domains(update.effective_chat.id)
    if not domains:
        return await update.message.reply_text("ยังไม่มี Blocked Domain")
    await update.message.reply_text("Blocked Domains:\n" + "\n".join(domains))

# ---------------- Group Analytics ----------------

async def cmd_groupstats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """สรุปภาพรวมกลุ่ม (คำฮิต + ช่วงเวลาแอคทีฟ) แบบไม่แยกรายบุคคล — Admin เท่านั้น"""
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
        
    summary = get_group_summary(update.effective_chat.id)
    if summary["total_messages"] == 0:
        return await update.message.reply_text("ยังไม่มีข้อมูลสถิติของกลุ่มนี้")
        
    words_text = "\n".join(
        f"{i+1}. {w} ({c})" for i, (w, c) in enumerate(summary["top_words"])
    ) or "-"
    hours_text = "\n".join(
        f"{h:02d}:00-{h:02d}:59 UTC ({c} ข้อความ)" for h, c in summary["top_hours"]
    ) or "-"

    text = (
        f"📊 สรุปภาพรวมกลุ่ม\n"
        f"ข้อความทั้งหมดที่บันทึก: {summary['total_messages']}\n\n"
        f"คำฮิต:\n{words_text}\n\n"
        f"ช่วงเวลาแอคทีฟสุด:\n{hours_text}"
    )
    await update.message.reply_text(text)
    
# ---------------- Bug Bounty Scope Policy (Phase 2) ----------------
#
# Telegram admin permission controls who may CREATE/MANAGE these records
# (same as every other admin command in this file). It is deliberately
# NOT what grants ALLOW — evaluate_target() in scope_policy.py has no
# is_admin parameter and cannot be short-circuited by chat role. A
# program only produces ALLOW once its Authorization has been reviewed
# via /bbauth review ... approve by a second, explicit step.

async def cmd_bbprogram(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    args = context.args
    usage = (
        "ใช้งาน:\n"
        "/bbprogram new <ชื่อโปรแกรม>\n"
        "/bbprogram active|pause|archive <program_id>\n"
        "/bbprogram list"
    )
    if not args:
        return await update.message.reply_text(usage)

    sub = args[0].lower()
    if sub == "new":
        name = " ".join(args[1:]).strip()
        if not name:
            return await update.message.reply_text("ใช้งาน: /bbprogram new <ชื่อโปรแกรม>")
        program_id = create_program(chat_id, name, created_by=user_id)
        return await update.message.reply_text(
            f"✅ สร้างโปรแกรมแล้ว #{program_id} “{name}” (สถานะ: PAUSED)\n"
            f"เปิดใช้งานด้วย: /bbprogram active {program_id}"
        )

    if sub in ("active", "pause", "archive"):
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text(f"ใช้งาน: /bbprogram {sub} <program_id>")
        program_id = int(args[1])
        status = {"active": ProgramStatus.ACTIVE.value, "pause": ProgramStatus.PAUSED.value,
                  "archive": ProgramStatus.ARCHIVED.value}[sub]
        ok = set_program_status(program_id, status, user_id)
        if not ok:
            return await update.message.reply_text(f"ไม่พบโปรแกรม #{program_id}")
        return await update.message.reply_text(f"✅ โปรแกรม #{program_id} -> {status}")

    if sub == "list":
        programs = list_programs(chat_id)
        if not programs:
            return await update.message.reply_text("ยังไม่มีโปรแกรมในกลุ่มนี้")
        lines = [f"#{p['program_id']} {p['name']} [{p['status']}]" for p in programs]
        return await update.message.reply_text("\n".join(lines))

    return await update.message.reply_text(usage)


async def cmd_bbauth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    user_id = update.effective_user.id
    args = context.args
    usage = (
        "ใช้งาน:\n"
        "/bbauth import <program_id> <source_type> [source_reference ...]\n"
        "/bbauth review <authorization_id> approve|reject [notes ...]\n"
        "/bbauth revoke <authorization_id>\n"
        "/bbauth list <program_id>"
    )
    if not args:
        return await update.message.reply_text(usage)

    sub = args[0].lower()
    if sub == "import":
        if len(args) < 3 or not args[1].isdigit():
            return await update.message.reply_text(
                "ใช้งาน: /bbauth import <program_id> <source_type> [source_reference ...]"
            )
        program_id = int(args[1])
        source_type = args[2]
        source_reference = " ".join(args[3:])
        authorization_id = import_authorization(
            program_id, source_type=source_type, actor_user_id=user_id,
            source_reference=source_reference,
        )
        if authorization_id is None:
            return await update.message.reply_text(f"ไม่พบโปรแกรม #{program_id}")
        return await update.message.reply_text(
            f"📥 บันทึกเอกสารสิทธิ์ #{authorization_id} สถานะ PENDING_REVIEW\n"
            f"ต้องได้รับการตรวจทานก่อนจึงจะมีผล: /bbauth review {authorization_id} approve"
        )

    if sub == "review":
        if len(args) < 3 or not args[1].isdigit() or args[2].lower() not in ("approve", "reject"):
            return await update.message.reply_text(
                "ใช้งาน: /bbauth review <authorization_id> approve|reject [notes ...]"
            )
        authorization_id = int(args[1])
        approve = args[2].lower() == "approve"
        review_notes = " ".join(args[3:])
        ok = review_authorization(authorization_id, approve=approve, reviewer_user_id=user_id,
                                   notes=review_notes)
        if not ok:
            return await update.message.reply_text(
                f"ไม่สามารถตรวจทาน #{authorization_id} ได้ (ไม่พบ หรือไม่ได้อยู่ในสถานะ PENDING_REVIEW)"
            )
        return await update.message.reply_text(
            f"✅ เอกสารสิทธิ์ #{authorization_id} -> {'ACTIVE' if approve else 'REJECTED'}"
        )

    if sub == "revoke":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbauth revoke <authorization_id>")
        authorization_id = int(args[1])
        ok = revoke_authorization(authorization_id, actor_user_id=user_id)
        if not ok:
            return await update.message.reply_text(f"ไม่สามารถเพิกถอน #{authorization_id} ได้")
        return await update.message.reply_text(f"✅ เพิกถอนเอกสารสิทธิ์ #{authorization_id} แล้ว")

    if sub == "list":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbauth list <program_id>")
        program_id = int(args[1])
        auths = list_authorizations(program_id)
        if not auths:
            return await update.message.reply_text(f"ยังไม่มีเอกสารสิทธิ์สำหรับโปรแกรม #{program_id}")
        lines = [
            f"#{a['authorization_id']} [{a['status']}] source={a['source_type']} "
            f"submitted_by={a['submitted_by'] or '-'} reviewed_by={a['reviewed_by'] or '-'}"
            for a in auths
        ]
        return await update.message.reply_text("\n".join(lines))

    return await update.message.reply_text(usage)


async def cmd_bbscope(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    user_id = update.effective_user.id
    args = context.args
    usage = (
        "ใช้งาน:\n"
        "/bbscope add <program_id> include|exclude domain|url|ip|cidr <pattern>\n"
        "/bbscope remove <rule_id>\n"
        "/bbscope list <program_id>"
    )
    if not args:
        return await update.message.reply_text(usage)

    sub = args[0].lower()
    if sub == "add":
        if len(args) < 5 or not args[1].isdigit():
            return await update.message.reply_text(
                "ใช้งาน: /bbscope add <program_id> include|exclude domain|url|ip|cidr <pattern>"
            )
        program_id = int(args[1])
        rule_type = args[2].upper()
        target_type = args[3].upper()
        pattern = args[4]
        if rule_type not in VALID_RULE_TYPES or target_type not in VALID_TARGET_TYPES:
            return await update.message.reply_text(
                "rule_type ต้องเป็น include/exclude, target_type ต้องเป็น domain/url/ip/cidr"
            )
        rule_id = add_scope_rule(program_id, rule_type, target_type, pattern, actor_user_id=user_id)
        if rule_id is None:
            return await update.message.reply_text(
                "❌ เพิ่มกฎไม่สำเร็จ — ตรวจสอบ program_id หรือรูปแบบ pattern "
                "(URL ต้องมี http:// หรือ https:// นำหน้า)"
            )
        return await update.message.reply_text(f"✅ เพิ่มกฎ #{rule_id}: {rule_type} {target_type} {pattern}")

    if sub == "remove":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbscope remove <rule_id>")
        rule_id = int(args[1])
        ok = remove_scope_rule(rule_id, actor_user_id=user_id)
        if not ok:
            return await update.message.reply_text(f"ไม่พบกฎ #{rule_id}")
        return await update.message.reply_text(f"✅ ลบกฎ #{rule_id} แล้ว")

    if sub == "list":
        if len(args) < 2 or not args[1].isdigit():
            return await update.message.reply_text("ใช้งาน: /bbscope list <program_id>")
        program_id = int(args[1])
        rules = list_scope_rules(program_id)
        if not rules:
            return await update.message.reply_text(f"ยังไม่มีกฎ scope สำหรับโปรแกรม #{program_id}")
        lines = [f"#{r['rule_id']} {r['rule_type']} {r['target_type']} {r['pattern']}" for r in rules]
        return await update.message.reply_text("\n".join(lines))

    return await update.message.reply_text(usage)


async def cmd_bbcheck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Read-only decision check. Admin-gated for now, like the rest of
    this command group — see the module-level note above this section."""
    if not await is_admin(update, context):
        return await update.message.reply_text("❌ คำสั่งนี้ใช้ได้เฉพาะ Admin")
    args = context.args
    if len(args) < 2 or not args[0].isdigit():
        return await update.message.reply_text("ใช้งาน: /bbcheck <program_id> <target>")
    program_id = int(args[0])
    target = args[1]
    decision = evaluate_target(program_id, target)
    icon = "✅ ALLOW" if decision.allowed else "⛔ DENY"
    text = f"{icon}\nprogram: #{program_id}\ntarget: {target}\nreason: {decision.reason}"
    if decision.detail:
        text += f"\ndetail: {decision.detail}"
    await update.message.reply_text(text)

# ---------------- Message Handler ----------------

async def check_auto_reply(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> bool:
    """Auto-reply เมื่อข้อความตรงกับ AUTO_REPLY_TRIGGERS
    - พิมพ์ครั้งที่ 1-3: ตอบข้อความปกติ
    - เกิน AUTO_REPLY_ANNOY_THRESHOLD (ครั้งที่ 4-5): ตอบข้อความรำคาญ
    - เกิน AUTO_REPLY_ANGRY_THRESHOLD (ครั้งที่ 6+): ตอบข้อความไม่สุภาพ
    นับโควต้าแยกตาม (chat_id, user_id, trigger) คนละคนคนละโควต้า
    คืนค่า True หากมีการตอบกลับแล้ว (handle_message ควร return ทันที)
    """
    trigger = text.strip()
    reply_text = AUTO_REPLY_TRIGGERS.get(trigger)
    if reply_text is None:
        return False
        
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    key = (chat_id, user_id, trigger)
    
    auto_reply_tracker[key] += 1
    count = auto_reply_tracker[key]
    
    if count > AUTO_REPLY_ANGRY_THRESHOLD:
        await update.message.reply_text(AUTO_REPLY_ANGRY_TEXT)
    elif count > AUTO_REPLY_ANNOY_THRESHOLD:
        await update.message.reply_text(AUTO_REPLY_ANNOYED_TEXT)
    else:
        await update.message.reply_text(reply_text)
        
    logger.info(
        f"AUTO REPLY | Chat ID: {chat_id} | User ID: {user_id} | "
        f"Trigger: {trigger!r} | Count: {count}"
    )
    return True
    
async def _run_ai_question(update: Update, context: ContextTypes.DEFAULT_TYPE, question: str,
                            reply_msg, media) -> None:
    """ตรวจโควตา เรียก coordinator แล้วตอบกลับผู้ใช้ — ใช้ร่วมกันทั้ง
    check_gemini_mention (แท็กบอทเป็นข้อความ) และ handle_media_message
    (แท็กบอทใน caption ของรูป/ไฟล์) เพื่อไม่ให้ logic โควตา/quota-message/
    error-handling สองที่เพี้ยนไปจากกัน"""
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    admin = await is_admin(update, context)
    allowed, used, limit = check_and_use_quota(chat_id, user_id, admin)
    if not allowed:
        await update.message.reply_text(
            f"ใช้งานเกินโควตาวันนี้แล้ว ({used}/{limit} ครั้ง) ไว้มาใช้วันอื่นนะ หรือถ้ารีบก็ไปใช้งานบนเว็บไป ไอ้ควาย ไม่ต้องมาใช้กู นอกจากจะเปลือง Token แล้วยังเปลืองออกซิเจนเพราะมึงแย่งหายใจอีก🖕🏻"
        )
        return
        
    logger.info(
        f"GEMINI MENTION | Chat ID: {chat_id} | User ID: {user_id} | "
        f"Question: {question} | Media: {'yes' if media else 'no'}"
    )
    await context.bot.send_chat_action(chat_id, ChatAction.TYPING)
    
    reply_user_id = reply_msg.from_user.id if reply_msg and reply_msg.from_user else None
    reply_text = reply_msg.text if reply_msg and reply_msg.text else None
    ok, result = await coordinator.handle_request(
        chat_id=chat_id,
        user_id=user_id,
        is_admin=admin,
        question=question,
        reply_user_id=reply_user_id,
        reply_text=reply_text,
        media=media,
    )
    if not ok:
        await update.message.reply_text(result)
        return
    for chunk in split_telegram_message(result):
        await update.message.reply_text(chunk)
    
async def check_gemini_mention(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str) -> bool:
    """ถาม AI เมื่อมีคนแท็กบอท เช่น '@ชื่อบอท คำถาม' ในแชท
    รองรับแนบรูปภาพ/ไฟล์ (PDF/TXT) ได้ด้วยการ Reply ข้อความที่มีรูป/เอกสารนั้น
    แล้วแท็กบอทพร้อมคำถาม — หรือแท็กเฉยๆ ก็ได้ถ้ามีรูป/ไฟล์แนบ (จะใช้คำถามเริ่มต้น)
    คืนค่า True หากมีการตอบกลับแล้ว (handle_message ควร return ทันที)"""
    message = update.effective_message
    bot_username = context.bot.username
    if not bot_username:
        return False
        
    entities = message.parse_entities(types=["mention"])
    mention_text = _find_bot_mention(entities, bot_username)
    if mention_text is None:
        return False
        
    question = text.replace(mention_text, "", 1).strip()
    
    reply_msg = update.message.reply_to_message
    media = None
    if reply_msg and (reply_msg.photo or reply_msg.document):
        media_bytes, media_mime, media_error = await extract_media_from_message(reply_msg, context)
        if media_error:
            await update.message.reply_text(media_error)
            return True
        if media_bytes:
            media = [(media_bytes, media_mime)]
            
    if not question:
        if media:
            question = DEFAULT_MEDIA_QUESTION
        else:
             await update.message.reply_text(
                f"พิมพ์คำถามต่อท้าย {mention_text} ได้เลย เช่น {mention_text} วันนี้พ่อกับแม่มึงเย็ดกันหรือยัง"
             )
             return True
            
    await _run_ai_question(update, context, question, reply_msg, media)
    return True
    
async def handle_media_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """แท็กบอทพร้อมแนบรูปภาพ/ไฟล์ในข้อความเดียว เช่น ส่งรูปแล้วใส่ caption
    '@ชื่อบอท นี่คือรูปอะไร' — ทำงานคู่กับ check_gemini_mention ซึ่งรองรับ
    กรณี Reply รูป/ไฟล์ที่ส่งไปก่อนหน้าแล้วแท็กบอทเป็นข้อความแยกต่างหาก"""
    message = update.effective_message
    if message is None or not message.caption:
        return
        
    bot_username = context.bot.username
    if not bot_username:
        return
        
    entities = message.parse_caption_entities(types=["mention"])
    mention_text = _find_bot_mention(entities, bot_username)
    if mention_text is None:
        return
        
    media_bytes, media_mime, media_error = await extract_media_from_message(message, context)
    if media_error:
        await update.message.reply_text(media_error)
        return
    if not media_bytes:
        return 
        
    question = message.caption.replace(mention_text, "", 1).strip() or DEFAULT_MEDIA_QUESTION
    await _run_ai_question(update, context, question, reply_msg=None, media=[(media_bytes, media_mime)])
    
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    message = update.effective_message
    if message is None or not message.text:
        return
    chat = update.effective_chat
    user = update.effective_user
    text = message.text
        
    logger.info(f"MESSAGE RECEIVED | Chat ID: {chat.id} | User ID: {user.id} | Text: {text}")
    if chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
        record_message_activity(chat.id, text)
        detection_results = detection.analyze_message(chat.id, user.id, text)
        if detection_results:
            worst = max(
                detection_results,
                key=lambda r: {"low": 0, "medium": 1, "high": 2}.get(r.severity, 0),
            )
            await safe_delete(message, chat.id, context)
            await apply_warning_and_maybe_mute(update, context, user.id, f"⚠️ {worst.reason}")
            return
    if await check_auto_reply(update, context, text):
            return
            
    if await check_gemini_mention(update, context, text):
            return
        
    settings = get_settings(chat.id)
        
    if settings["antispam_on"]:
        now = time.time()
        dq = spam_tracker[(chat.id, user.id)]
        dq.append(now)
        while dq and now - dq[0] > SPAM_TIME_WINDOW:
            dq.popleft()
        if len(dq) > SPAM_MESSAGE_LIMIT:
            logger.info(f"SPAM DETECTED | Chat ID: {chat.id} | User ID: {user.id}")
            await safe_delete(message, chat.id, context)
            await apply_warning_and_maybe_mute(update, context, user.id, "⚠️ ส่งข้อความเหี้ยไรบ่อยนักหนา ไอ้นรก")
            dq.clear()
            return
        
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id
            
    logger.info(f"FILTER: {'ON' if settings['filter_on'] else 'OFF'}")
    if settings["filter_on"]:
        words = list_words(chat.id)
        matched = contains_forbidden_word(text, words)
        if matched:
            logger.info(f"MATCHED WORD: {matched}\nACTION: DELETE")
            await safe_delete(message, chat.id, context)
            await apply_warning_and_maybe_mute(update, context, user.id, "🚫 ตรวจพบพวกลาบใช้คำต้องห้าม")
        else:
            logger.info("MATCHED WORD: NONE\nACTION: IGNORE")

async def error_handler(update, context):
    logger.error("UNHANDLED ERROR", exc_info=context.error)
    
async def post_init(app):
    app.bot_data["news_task"] = asyncio.create_task(news_background_loop(app.bot))
    
async def post_shutdown(app):
    task = app.bot_data.get("news_task")
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    
# ---------------- Main ----------------

def main():
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set. Please check .env file")
        
    logger.info("BOT STARTING")
    db_info()
    quota_db_init()
    security_db_init()
    analytics_db_init()
    news_db_init()
    detection.detection_db_init()
    logger.info("DATABASE: OK")
    
    app = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )
    
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("filter_on", cmd_filter_on))
    app.add_handler(CommandHandler("filter_off", cmd_filter_off))
    app.add_handler(CommandHandler("addword", cmd_addword))
    app.add_handler(CommandHandler("delword", cmd_delword))
    app.add_handler(CommandHandler("listwords", cmd_listwords))
    app.add_handler(CommandHandler("warnings", cmd_warnings))
    app.add_handler(CommandHandler("resetwarn", cmd_resetwarn))
    app.add_handler(CommandHandler("mute", cmd_mute))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CommandHandler("announce", cmd_announce))
    app.add_handler(CommandHandler("imagine", cmd_imagine))
    app.add_handler(CommandHandler("groupstats", cmd_groupstats))
    app.add_handler(CommandHandler("dashboard", dashboard_command))
    app.add_handler(CommandHandler("id", chat_id_command))
    app.add_handler(CommandHandler("identity", cmd_personal_identity))
    app.add_handler(CommandHandler("corporate", cmd_corporate_espionage))
    app.add_handler(CommandHandler("bbprogram", cmd_bbprogram))
    app.add_handler(CommandHandler("bbauth", cmd_bbauth))
    app.add_handler(CommandHandler("bbscope", cmd_bbscope))
    app.add_handler(CommandHandler("bbcheck", cmd_bbcheck))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(
        filters.PHOTO & filters.CaptionRegex(IMAGINE_CAPTION_RE),
        handle_imagine_caption,
    ))
    app.add_handler(MessageHandler(
        (filters.PHOTO | filters.Document.ALL) & filters.CAPTION
        & ~filters.CaptionRegex(IMAGINE_CAPTION_RE) & ~filters.COMMAND,
        handle_media_message,
    ))
    app.add_error_handler(error_handler)

    logger.info("HANDLERS: OK")
    logger.info("POLLING: STARTED")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()