# -*- coding: utf-8 -*-
"""autolink/store.py — ชั้นจัดเก็บของระบบส่งลิงก์อัตโนมัติ (atomic JSON)

เก็บทุกอย่างในไฟล์ JSON เดียว แยก namespace ตาม chat_id เขียนแบบ atomic
(temp + os.replace) กันไฟล์เสียเวลาไฟดับ/โดน kill กลางคัน — แนวทางเดียวกับ
reputation.py ของโปรเจกต์

สคีมา
-----
{
  "chats": {
    "<chat_id>": {
      "seq": 3,                     # ตัวนับ id แคมเปญถัดไป
      "campaigns": {
        "1": {
          "id": 1,
          "title": "โปรโมทเว็บ",
          "links": [{"url": "...", "label": "..."}],
          "interval_sec": 1800,
          "mode": "sequential",     # sequential | random | single
          "cursor": 0,
          "enabled": true,
          "silent": false,          # ปิดเสียงแจ้งเตือนตอนส่ง
          "preview": true,          # แสดงพรีวิวลิงก์
          "template": "",           # ข้อความห่อลิงก์ (รองรับ {url}{label}{n}{total})
          "jitter_sec": 0,          # สุ่มหน่วงเพิ่ม 0..jitter กันดูเป็นบอท
          "created_iso": "...",
          "last_run_iso": null,
          "runs": 0
        }
      }
    }
  }
}

โมดูลนี้เป็น pure storage ล้วน ไม่ยุ่งกับ Telegram และรับ now เข้ามาได้เพื่อเทสต์
"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.autolink.store")

# path ไฟล์ DB — override ได้ด้วย env AUTOLINK_DB
DB_PATH = os.getenv("AUTOLINK_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "resource", "autolink.json",
)

# เพดานเชิงระบบ กันไฟล์บวม/กันยิงถี่จนโดนแบน
MAX_CAMPAIGNS_PER_CHAT = int(os.getenv("AUTOLINK_MAX_CAMPAIGNS", "50") or "50")
MAX_LINKS_PER_CAMPAIGN = int(os.getenv("AUTOLINK_MAX_LINKS", "200") or "200")
MIN_INTERVAL_SEC = int(os.getenv("AUTOLINK_MIN_INTERVAL", "15") or "15")

VALID_MODES = ("sequential", "random", "single")


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
# โหลด/เขียน
# ---------------------------------------------------------------------------

def _db_path(path: Optional[str]) -> str:
    return path or DB_PATH


def load(path: Optional[str] = None) -> Dict[str, Any]:
    """โหลด DB — คืนโครงว่างถ้าไฟล์ไม่มี/อ่านไม่ได้ (ไม่ throw)"""
    target = _db_path(path)
    try:
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("root is not an object")
        data.setdefault("chats", {})
        return data
    except FileNotFoundError:
        return {"chats": {}}
    except (json.JSONDecodeError, ValueError, OSError) as e:
        logger.error("AUTOLINK DB LOAD FAILED (%s) — starting empty", e)
        return {"chats": {}}


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    """เขียน DB แบบ atomic (เขียน temp แล้ว os.replace ทับ)"""
    target = _db_path(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".autolink.", suffix=".tmp", dir=parent)
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
# ตัวช่วยเข้าถึงโครง
# ---------------------------------------------------------------------------

def _chat(db: Dict[str, Any], chat_id) -> Dict[str, Any]:
    chats = db.setdefault("chats", {})
    key = str(chat_id)
    node = chats.get(key)
    if node is None:
        node = {"seq": 0, "campaigns": {}}
        chats[key] = node
    node.setdefault("seq", 0)
    node.setdefault("campaigns", {})
    return node


def get_campaign(db: Dict[str, Any], chat_id, cid) -> Optional[Dict[str, Any]]:
    chat = db.get("chats", {}).get(str(chat_id))
    if not chat:
        return None
    return chat.get("campaigns", {}).get(str(cid))


def list_campaigns(db: Dict[str, Any], chat_id) -> List[Dict[str, Any]]:
    chat = db.get("chats", {}).get(str(chat_id))
    if not chat:
        return []
    out = list(chat.get("campaigns", {}).values())
    out.sort(key=lambda c: c.get("id", 0))
    return out


def iter_all(db: Dict[str, Any]):
    """yield (chat_id_str, campaign) ทุกแคมเปญทุกห้อง"""
    for chat_id, node in db.get("chats", {}).items():
        for c in node.get("campaigns", {}).values():
            yield chat_id, c


# ---------------------------------------------------------------------------
# สร้าง/แก้ (load-modify-write ภายในฟังก์ชันเดียว ปลอดภัยต่อการเรียกพร้อมกัน)
# ---------------------------------------------------------------------------

def _blank_campaign(cid: int, links: List[Dict[str, str]], interval_sec: int,
                    title: str, now: datetime) -> Dict[str, Any]:
    return {
        "id": cid,
        "title": title or f"campaign-{cid}",
        "links": links,
        "interval_sec": int(interval_sec),
        "mode": "sequential",
        "cursor": 0,
        "enabled": True,
        "silent": False,
        "preview": True,
        "template": "",
        "jitter_sec": 0,
        "created_iso": iso(now),
        "last_run_iso": None,
        "runs": 0,
    }


def create_campaign(chat_id, links: List[Dict[str, str]], interval_sec: int,
                    title: str = "", now: Optional[datetime] = None,
                    path: Optional[str] = None) -> Dict[str, Any]:
    """สร้างแคมเปญใหม่ คืน dict แคมเปญที่สร้าง — raise ValueError ถ้าเกินเพดาน"""
    now = now or utcnow()
    db = load(path)
    chat = _chat(db, chat_id)
    if len(chat["campaigns"]) >= MAX_CAMPAIGNS_PER_CHAT:
        raise ValueError(f"เกินเพดานจำนวนแคมเปญต่อห้อง ({MAX_CAMPAIGNS_PER_CHAT})")
    if not links:
        raise ValueError("ต้องมีอย่างน้อย 1 ลิงก์")
    if len(links) > MAX_LINKS_PER_CAMPAIGN:
        raise ValueError(f"เกินเพดานจำนวนลิงก์ต่อแคมเปญ ({MAX_LINKS_PER_CAMPAIGN})")
    if interval_sec < MIN_INTERVAL_SEC:
        raise ValueError(f"ช่วงเวลาสั้นเกินไป ขั้นต่ำ {MIN_INTERVAL_SEC} วินาที")

    chat["seq"] = int(chat.get("seq", 0)) + 1
    cid = chat["seq"]
    camp = _blank_campaign(cid, links, interval_sec, title, now)
    chat["campaigns"][str(cid)] = camp
    save(db, path)
    return camp


def update_campaign(chat_id, cid, mutate, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """load-modify-write: เรียก mutate(campaign) เพื่อแก้ แล้วเขียนกลับ

    mutate อาจ raise ValueError เพื่อปฏิเสธการแก้ (จะไม่เขียนไฟล์)
    คืนแคมเปญหลังแก้ หรือ None ถ้าไม่พบ
    """
    db = load(path)
    camp = get_campaign(db, chat_id, cid)
    if camp is None:
        return None
    mutate(camp)
    save(db, path)
    return camp


def delete_campaign(chat_id, cid, path: Optional[str] = None) -> bool:
    db = load(path)
    chat = db.get("chats", {}).get(str(chat_id))
    if not chat or str(cid) not in chat.get("campaigns", {}):
        return False
    del chat["campaigns"][str(cid)]
    save(db, path)
    return True


def mark_ran(chat_id, cid, new_cursor: int, now: Optional[datetime] = None,
             path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """บันทึกว่าแคมเปญเพิ่งส่งไป: อัปเดต last_run / cursor / runs (fresh load-write)"""
    now = now or utcnow()

    def _mut(c):
        c["last_run_iso"] = iso(now)
        c["cursor"] = int(new_cursor)
        c["runs"] = int(c.get("runs", 0)) + 1

    return update_campaign(chat_id, cid, _mut, path)
