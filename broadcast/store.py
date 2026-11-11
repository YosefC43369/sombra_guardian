# -*- coding: utf-8 -*-
"""broadcast/store.py — ชั้นเก็บข้อมูลของตัวกระจายลิงก์ (atomic JSON)

ต่างจาก autolink: autolink โพสต์ "ในห้องตัวเอง" ส่วน broadcast ยิงลิงก์ "ออกไป
ยังห้อง/คนอื่น" ตามทะเบียนปลายทาง (targets) ที่บอตเข้าถึงได้

เก็บสองส่วนในไฟล์เดียว:
  config   ลิงก์เดียว + ความถี่ + สวิตช์เปิด/ปิด + ตัวเลือกการส่ง
  targets  ทะเบียนปลายทาง {chat_id -> ข้อมูล} เติมได้ทั้งมือและอัตโนมัติ

pure storage — ไม่ import telegram, รับ now เข้ามาได้เพื่อเทสต์
"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.broadcast.store")

DB_PATH = os.getenv("BROADCAST_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "resource", "broadcast.json",
)

MAX_TARGETS = int(os.getenv("BROADCAST_MAX_TARGETS", "5000") or "5000")
MIN_INTERVAL_SEC = int(os.getenv("BROADCAST_MIN_INTERVAL", "60") or "60")
# ลบปลายทางทิ้งอัตโนมัติเมื่อส่งพลาดชนิด "ถาวร" ติดกันครบกี่ครั้ง
MAX_FAILS_BEFORE_DROP = int(os.getenv("BROADCAST_MAX_FAILS", "3") or "3")


# ---------------------------------------------------------------------------
# เวลา
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# โหลด/เขียน atomic
# ---------------------------------------------------------------------------

def _default_config() -> Dict[str, Any]:
    return {
        "link": "",
        "template": "",         # ไม่ตั้ง -> ส่งลิงก์เปล่า (หรือ message + ลิงก์)
        "message": "",          # ข้อความนำหน้าลิงก์ (ถ้าไม่ใช้ template)
        "interval_sec": 3600,
        "enabled": False,       # ดีฟอลต์ปิด — ต้องสั่งเปิดเองเสมอ
        "silent": False,
        "preview": True,
        "collect": True,        # auto-remember ห้อง/แชตที่บอตเห็น
        "per_send_delay_ms": 50,  # หน่วงระหว่างปลายทาง กันชน flood limit
        "last_run_iso": None,
        "runs": 0,
    }


def _db_path(path: Optional[str]) -> str:
    return path or DB_PATH


def load(path: Optional[str] = None) -> Dict[str, Any]:
    target = _db_path(path)
    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("root is not an object")
    except FileNotFoundError:
        data = {}
    except (json.JSONDecodeError, ValueError, OSError) as e:
        logger.error("BROADCAST DB LOAD FAILED (%s) — starting empty", e)
        data = {}
    cfg = _default_config()
    cfg.update(data.get("config", {}) if isinstance(data.get("config"), dict) else {})
    data["config"] = cfg
    data.setdefault("targets", {})
    if not isinstance(data["targets"], dict):
        data["targets"] = {}
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _db_path(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".broadcast.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def get_config(path: Optional[str] = None) -> Dict[str, Any]:
    return load(path)["config"]


def update_config(mutate, path: Optional[str] = None) -> Dict[str, Any]:
    """load-modify-write ของ config — mutate(cfg) อาจ raise ValueError เพื่อปฏิเสธ"""
    db = load(path)
    mutate(db["config"])
    save(db, path)
    return db["config"]


# ---------------------------------------------------------------------------
# targets
# ---------------------------------------------------------------------------

def _blank_target(chat_id: int, title: str, ctype: str, source: str,
                  now: datetime) -> Dict[str, Any]:
    return {
        "chat_id": int(chat_id),
        "title": title or str(chat_id),
        "type": ctype or "unknown",
        "source": source,
        "added_iso": iso(now),
        "last_ok_iso": None,
        "fails": 0,
        "muted": False,
    }


def list_targets(db: Dict[str, Any], include_muted: bool = True) -> List[Dict[str, Any]]:
    out = list(db.get("targets", {}).values())
    if not include_muted:
        out = [t for t in out if not t.get("muted")]
    out.sort(key=lambda t: t.get("added_iso") or "")
    return out


def get_target(db: Dict[str, Any], chat_id) -> Optional[Dict[str, Any]]:
    return db.get("targets", {}).get(str(chat_id))


def add_target(chat_id, title: str = "", ctype: str = "", source: str = "manual",
               now: Optional[datetime] = None, path: Optional[str] = None
               ) -> Dict[str, Any]:
    """เพิ่ม/อัปเดตปลายทาง คืน record — raise ValueError ถ้าเกินเพดาน"""
    now = now or utcnow()
    db = load(path)
    targets = db["targets"]
    key = str(chat_id)
    if key in targets:
        # อัปเดตชื่อ/ประเภทถ้ามีข้อมูลใหม่ (ไม่รีเซ็ตสถิติ)
        if title:
            targets[key]["title"] = title
        if ctype:
            targets[key]["type"] = ctype
        save(db, path)
        return targets[key]
    if len(targets) >= MAX_TARGETS:
        raise ValueError(f"เกินเพดานจำนวนปลายทาง ({MAX_TARGETS})")
    rec = _blank_target(int(chat_id), title, ctype, source, now)
    targets[key] = rec
    save(db, path)
    return rec


def remember(chat_id, title: str = "", ctype: str = "",
             path: Optional[str] = None) -> bool:
    """auto-register ปลายทางจากข้อความที่บอตเห็น — ทำงานเฉพาะเมื่อ config.collect=on

    คืน True ถ้าบันทึก/อัปเดต, False ถ้าปิด collect หรือเต็มเพดาน (เงียบ ไม่ throw)
    """
    try:
        db = load(path)
        if not db["config"].get("collect", True):
            return False
        key = str(chat_id)
        targets = db["targets"]
        if key in targets:
            changed = False
            if title and targets[key].get("title") != title:
                targets[key]["title"] = title
                changed = True
            if ctype and targets[key].get("type") != ctype:
                targets[key]["type"] = ctype
                changed = True
            if changed:
                save(db, path)
            return changed
        if len(targets) >= MAX_TARGETS:
            return False
        targets[key] = _blank_target(int(chat_id), title, ctype, "auto", utcnow())
        save(db, path)
        return True
    except Exception:
        logger.exception("BROADCAST remember failed | chat=%s", chat_id)
        return False


def del_target(chat_id, path: Optional[str] = None) -> bool:
    db = load(path)
    key = str(chat_id)
    if key not in db.get("targets", {}):
        return False
    del db["targets"][key]
    save(db, path)
    return True


def clear_targets(path: Optional[str] = None) -> int:
    db = load(path)
    n = len(db.get("targets", {}))
    db["targets"] = {}
    save(db, path)
    return n


def set_muted(chat_id, muted: bool, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    db = load(path)
    t = get_target(db, chat_id)
    if not t:
        return None
    t["muted"] = bool(muted)
    save(db, path)
    return t


def record_result(chat_id, ok: bool, drop: bool = False,
                  now: Optional[datetime] = None, path: Optional[str] = None) -> None:
    """บันทึกผลส่งต่อปลายทางหนึ่ง (fresh load-write)

    ok=True   -> ล้างตัวนับพลาด, จด last_ok
    ok=False  -> นับพลาด; ถ้า drop=True (พลาดถาวร เช่นโดนบล็อก/เตะ) ลบทิ้งเลย
                  หรือถ้าพลาดสะสมครบ MAX_FAILS_BEFORE_DROP ก็ลบทิ้ง
    """
    now = now or utcnow()
    db = load(path)
    t = get_target(db, chat_id)
    if not t:
        return
    key = str(chat_id)
    if ok:
        t["fails"] = 0
        t["last_ok_iso"] = iso(now)
    else:
        t["fails"] = int(t.get("fails", 0)) + 1
        if drop or t["fails"] >= MAX_FAILS_BEFORE_DROP:
            db["targets"].pop(key, None)
    save(db, path)


def mark_broadcast_ran(now: Optional[datetime] = None, path: Optional[str] = None) -> None:
    now = now or utcnow()

    def _mut(cfg):
        cfg["last_run_iso"] = iso(now)
        cfg["runs"] = int(cfg.get("runs", 0)) + 1

    update_config(_mut, path)
