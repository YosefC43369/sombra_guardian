# -*- coding: utf-8 -*-
"""notes.py — "คลังบันทึกกลุ่ม" (Group Notes / Saved Tags)

แนวคิด
------
ให้แต่ละกลุ่มเก็บ "คำตอบ/ประกาศ/กฎ/ลิงก์" ที่ใช้ซ้ำบ่อย ๆ ไว้ตาม keyword แล้วสมาชิก
เรียกดูได้ทันที — เหมือนคลังความรู้/แคนคำตอบของกลุ่ม (feature ยอดนิยมของบอตดูแลกลุ่ม)

  Admin:  /note add <key> <ข้อความ>   บันทึก/ทับ
          /note del <key>             ลบ
  ทุกคน:  /note <key>                 เรียกดู
          /note list  หรือ  /notes    รายการ keyword ทั้งหมด

ออกแบบ
------
- พึ่งพาเฉพาะไลบรารีมาตรฐาน (เทสต์ได้ง่าย ไม่ต้องมี dependency ภายนอก)
- เก็บเป็นไฟล์ JSON เดียว แยก namespace ตาม chat_id — เขียนแบบ atomic กันไฟล์เสีย
- ไม่ใช่ข้อมูลส่วนบุคคล: เป็นเนื้อหาที่สมาชิกกลุ่มตั้งใจบันทึกเอง (บันทึกผู้เขียน/เวลา/
  จำนวนครั้งที่เรียก เพื่อความโปร่งใส)
- การตรวจสิทธิ์ Admin ทำที่ชั้น handler ใน app.py (โมดูลนี้เป็น storage ล้วน ๆ)
"""

import os
import io
import re
import json
import logging
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("modbot.notes")

# ที่อยู่ไฟล์คลังบันทึก — override ได้ด้วย env NOTES_DB
DB_PATH = os.getenv("NOTES_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "resource", "notes.json")

# เพดานกันการใช้เกินควร
MAX_NOTES_PER_CHAT = int(os.getenv("NOTES_MAX_PER_CHAT", "200") or "200")
MAX_KEY_LEN = int(os.getenv("NOTES_MAX_KEY_LEN", "40") or "40")
MAX_TEXT_LEN = int(os.getenv("NOTES_MAX_TEXT_LEN", "4000") or "4000")

# key = โทเคนเดียว (อักษร/ตัวเลข/ไทย + _-.) ไม่มีช่องว่าง
_RE_KEY_STRIP = re.compile(r"^[#/]+")
_RE_KEY_OK = re.compile(r"^[a-z0-9ก-๙_\-.]{1,%d}$" % MAX_KEY_LEN)

# แคช DB ใน RAM ตาม mtime (อ่านซ้ำ ๆ ไม่ต้องแตะดิสก์)
_cache = {"path": None, "mtime": None, "db": None}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _db_path(path: Optional[str] = None) -> str:
    return path or DB_PATH


def normalize_key(key: str) -> Optional[str]:
    """ทำ key ให้เป็นมาตรฐาน (ตัด #// นำหน้า, ตัดช่องว่าง, ตัวพิมพ์เล็ก) — None ถ้าไม่ถูกต้อง"""
    if not key:
        return None
    k = _RE_KEY_STRIP.sub("", str(key).strip()).strip().lower()
    if not k or " " in k or not _RE_KEY_OK.match(k):
        return None
    return k


def _load(path: Optional[str] = None) -> dict:
    """โหลดคลังบันทึกทั้งไฟล์ (แคชตาม mtime) — คืน {} ถ้าไม่มีไฟล์/อ่านไม่ได้ (ไม่ throw)"""
    target = _db_path(path)
    try:
        mtime = os.path.getmtime(target)
    except OSError:
        return {}
    if _cache["path"] == target and _cache["mtime"] == mtime and _cache["db"] is not None:
        return _cache["db"]
    try:
        with io.open(target, "r", encoding="utf-8") as f:
            db = json.load(f)
        if not isinstance(db, dict):
            db = {}
    except (OSError, ValueError) as e:
        logger.warning("NOTES | อ่านไฟล์ไม่ได้ %s (%s)", target, e)
        return {}
    _cache.update(path=target, mtime=mtime, db=db)
    return db


def _atomic_write(db: dict, path: Optional[str] = None) -> None:
    """เขียนไฟล์แบบ atomic (temp + os.replace) กันไฟล์เสียหายถ้าถูกขัดจังหวะ"""
    target = _db_path(path)
    parent = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".notes.", suffix=".tmp", dir=parent)
    try:
        with io.open(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # invalidate แคชให้รอบหน้าอ่านใหม่ตาม mtime
    _cache.update(path=None, mtime=None, db=None)


def _chat_notes(db: dict, chat_id) -> dict:
    return db.get(str(chat_id), {})


# ---------------- operations ----------------

def add_note(chat_id, key: str, text: str, author: Optional[str] = None,
             path: Optional[str] = None) -> dict:
    """บันทึก/ทับ note — คืน {"ok":bool, "error":str|None, "key":.., "replaced":bool}"""
    k = normalize_key(key)
    if not k:
        return {"ok": False, "error": "bad_key", "key": None}
    text = (text or "").strip()
    if not text:
        return {"ok": False, "error": "empty_text", "key": k}
    if len(text) > MAX_TEXT_LEN:
        return {"ok": False, "error": "too_long", "key": k}
    db = dict(_load(path))
    chat = dict(db.get(str(chat_id), {}))
    replaced = k in chat
    if not replaced and len(chat) >= MAX_NOTES_PER_CHAT:
        return {"ok": False, "error": "limit", "key": k}
    prev = chat.get(k) or {}
    chat[k] = {
        "text": text,
        "author": str(author) if author is not None else prev.get("author"),
        "created_at": prev.get("created_at") or _now_iso(),
        "updated_at": _now_iso(),
        "uses": int(prev.get("uses", 0)),
    }
    db[str(chat_id)] = chat
    _atomic_write(db, path)
    return {"ok": True, "error": None, "key": k, "replaced": replaced}


def get_note(chat_id, key: str, bump: bool = False, path: Optional[str] = None) -> Optional[dict]:
    """ดึง note ตาม key — คืน dict {text,author,uses,...} หรือ None ถ้าไม่มี

    bump=True จะเพิ่มตัวนับ uses (เรียกตอนสมาชิกเรียกดูจริง)
    """
    k = normalize_key(key)
    if not k:
        return None
    note = _chat_notes(_load(path), chat_id).get(k)
    if note is None:
        return None
    if bump:
        try:
            db = dict(_load(path))
            chat = dict(db.get(str(chat_id), {}))
            if k in chat:
                chat[k] = dict(chat[k])
                chat[k]["uses"] = int(chat[k].get("uses", 0)) + 1
                db[str(chat_id)] = chat
                _atomic_write(db, path)
                note = chat[k]
        except Exception as e:
            logger.debug("NOTES | bump uses ล้มเหลว (%s)", e)
    return dict(note)


def del_note(chat_id, key: str, path: Optional[str] = None) -> bool:
    """ลบ note — คืน True ถ้ามีและลบสำเร็จ"""
    k = normalize_key(key)
    if not k:
        return False
    db = dict(_load(path))
    chat = dict(db.get(str(chat_id), {}))
    if k not in chat:
        return False
    chat.pop(k, None)
    if chat:
        db[str(chat_id)] = chat
    else:
        db.pop(str(chat_id), None)   # กลุ่มไม่เหลือ note -> เก็บกวาด namespace
    _atomic_write(db, path)
    return True


def list_notes(chat_id, path: Optional[str] = None) -> List[str]:
    """คืนรายชื่อ key ทั้งหมดของกลุ่ม (เรียงตามตัวอักษร)"""
    return sorted(_chat_notes(_load(path), chat_id).keys())


def note_count(chat_id, path: Optional[str] = None) -> int:
    return len(_chat_notes(_load(path), chat_id))


# ---------------- formatting (Telegram) ----------------

_DIVIDER = "━━━━━━━━━━━━━━━━━━"


def format_note(key: str, note: dict) -> str:
    """จัดข้อความ note เดียวสำหรับส่งในแชท"""
    text = (note or {}).get("text", "")
    uses = int((note or {}).get("uses", 0))
    foot = f"\n{_DIVIDER}\n🔖 #{key}" + (f" · 👁️ {uses} ครั้ง" if uses else "")
    return f"📌 {text}{foot}"


def format_list(chat_id, keys: List[str]) -> str:
    """จัดข้อความรายการ key ทั้งหมด"""
    if not keys:
        return ("📁 คลังบันทึกกลุ่ม · ยังว่าง\n"
                f"{_DIVIDER}\n"
                "แอดมินเพิ่มได้ด้วย /note add <คำ> <ข้อความ>\nแล้วเรียกดูด้วย /note <คำ>")
    lines = [f"📁 คลังบันทึกกลุ่ม · {len(keys)} รายการ", _DIVIDER]
    lines += [f"🔖 #{k}" for k in keys]
    lines.append(_DIVIDER)
    lines.append("💡 เรียกดู: /note <คำ>")
    return "\n".join(lines)
