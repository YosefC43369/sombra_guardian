"""
gemini.py — Google Gemini API integration for the Telegram moderation bot.

Responsibilities (and only these):
  - Read GEMINI_API_KEY / GEMINI_MODEL from the environment at call time
    (never hardcoded, never read at import time — see note below).
  - Validate user input before it is sent to Gemini (empty / too long).
  - Call the Gemini API asynchronously so the bot's event loop is never
    blocked while waiting for a response.
  - Translate every failure mode (missing/invalid key, quota, rate limit,
    timeout, network error, empty response, unexpected exception) into a
    safe, Thai, user-facing message. Never raises out to bot.py and never
    leaks the API key or a stack trace to a Telegram user.
  - Split long Gemini responses into Telegram-safe chunks (<=4096 chars).

Environment variables are read lazily (inside functions, not at module
import time): bot.py calls load_dotenv() AFTER its own import block, so
reading os.environ at import time here would run before .env is loaded
during local development.

gemini.py never talks to Telegram directly and never touches the SQLite
database — that stays in bot.py / security.py, matching the separation
of concerns already used by detection.py.
"""

import os
import asyncio
import logging
from typing import Optional, Tuple, List

from google import genai
from google.genai import types, errors

logger = logging.getLogger("modbot.gemini")

# ---------------- Config (defaults; overridable via env) ----------------

GEMINI_MODEL_DEFAULT = "gemini-3.6-flash"
GEMINI_TIMEOUT_SECONDS = 30      # hard local cutoff for one Gemini call
GEMINI_MAX_INPUT_CHARS = 4000    # reject messages longer than this
TELEGRAM_MESSAGE_LIMIT = 4096    # Telegram's hard per-message character cap

_GENERIC_ERROR_TEXT = "ขออภัย ระบบ AI เอ๋อ กรุณาลองใหม่อีกครั้ง ถ้ารีบก็ไปใช้ตัวอื่นไป ไอ้ควาย"

_client: Optional[genai.Client] = None

def _get_client() -> genai.Client:
    """Lazily builds a single shared Client the first time it's needed.
    Raises RuntimeError if GEMINI_API_KEY is missing — ask_gemini always
    catches this and turns it into a safe Thai message."""
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not set")
        _client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=GEMINI_TIMEOUT_SECONDS * 1000),
        )
    return _client
    
# ---------------- Input validation ----------------
  
def _validate_input(text: str) -> Optional[str]:
    """Returns a Thai error message if `text` should not be sent to
    Gemini, else None. Kept local to this module: detection.py/security.py
    only cover moderation checks (spam/links/mentions), not general
    LLM-input sanity, so there is nothing to reuse there."""
    if text is None or not text.strip():
        return "กรุณาพิมพ์ข้อความที่ต้องการถามหลังคำสั่ง เช่น /ask สวัสดี"
    if len(text) > GEMINI_MAX_INPUT_CHARS:
        return f"ข้อความยาวเกินไป (จำกัด {GEMINI_MAX_INPUT_CHARS} ตัวอักษร)"
    return None


# ---------------- Gemini call ----------------

async def ask_gemini(prompt: str) -> Tuple[bool, str]:
    """Sends `prompt` to Gemini and returns (success, text).

    On success: text is the model's reply.
    On failure: text is a safe, Thai, user-facing message — never a
    stack trace, never the API key. Every exception is caught here; this
    function never raises, so a Gemini outage can never crash the bot
    process or the polling loop.
    """
    validation_error = _validate_input(prompt)
    if validation_error:
        return False, validation_error

    try:
        client = _get_client()
    except RuntimeError:
        logger.error("GEMINI CALL BLOCKED: GEMINI_API_KEY is not set")
        return False, "ยังไม่ได้ตั้งค่า API Key บนเซิร์ฟเวอร์ กรุณาติดต่อผู้ดูแลระบบ"

    model = os.getenv("GEMINI_MODEL", GEMINI_MODEL_DEFAULT)

    try:
        response = await asyncio.wait_for(
            client.aio.models.generate_content(
                model=model,
                contents=prompt.strip(),
            ),
            timeout=GEMINI_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning(f"GEMINI TIMEOUT after {GEMINI_TIMEOUT_SECONDS}s")
        return False, "AI ตอบกลับช้าเกินไปว่ะ ลองใหม่อีกครั้งดู"
    except errors.APIError as e:
        code = getattr(e, "code", None)
        logger.warning(f"GEMINI API ERROR | code={code} | {e}")
        if code in (401, 403):
            return False, "Gemini API Key ไม่ถูกต้องหรือมึงไม่มีสิทธิ์ใช้งาน"
        if code == 429:
            return False, "ใช้งานเกินโควตาหรือถูกจำกัดอัตราการใช้งานแล้ว ค่อยมาใช้วันอื่นใหม่นะ ไอ้โง่"
        if code and code >= 500:
            return False, "Gemini API ไม่พร้อมใช้งานในขณะนี้ กรุณาลองใหม่ภายหลัง"
        return False, _GENERIC_ERROR_TEXT
    except Exception:
        logger.exception("GEMINI UNEXPECTED ERROR")
        return False, _GENERIC_ERROR_TEXT

    text = (getattr(response, "text", None) or "").strip()
    if not text:
        logger.warning("GEMINI EMPTY RESPONSE")
        return False, "Gemini ไม่ได้ส่งคำตอบกลับมา กรุณาลองใหม่อีกครั้ง"

    return True, text


# ---------------- Telegram message splitting ----------------

def split_telegram_message(text: str, limit: int = TELEGRAM_MESSAGE_LIMIT) -> List[str]:
    """Splits `text` into chunks that fit Telegram's per-message limit,
    preferring to break on a paragraph, then line, then sentence/word
    boundary so words are not cut mid-way. Falls back to a hard cut only
    if a single unbroken token is itself longer than `limit`."""
    text = text.strip()
    if len(text) <= limit:
        return [text]

    chunks: List[str] = []
    remaining = text
    while len(remaining) > limit:
        window = remaining[:limit]
        split_at = max(
            window.rfind("\n\n"),
            window.rfind("\n"),
            window.rfind(". "),
            window.rfind(" "),
        )
        if split_at <= 0:
            split_at = limit
        chunks.append(remaining[:split_at].strip())
        remaining = remaining[split_at:].strip()
    if remaining:
        chunks.append(remaining)
    return chunks