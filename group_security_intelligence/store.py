# -*- coding: utf-8 -*-
"""group_security_intelligence/store.py — ชั้นเก็บข้อมูลของชั้นข่าวกรองความปลอดภัยกลุ่ม

เก็บ snapshot/ทะเบียน/ผลตรวจ/เหตุการณ์ แยก namespace ตาม chat_id ในไฟล์ JSON เดียว
เขียนแบบ atomic (temp + os.replace + fsync) — แนวทางเดียวกับ reputation/autolink/broadcast

สิ่งที่เก็บต่อ chat:
  policy          เกณฑ์/สวิตช์ที่ปรับได้ (ไม่ hardcode)
  admins          snapshot โครงแอดมินล่าสุด (จาก Bot API เท่านั้น)
  config          snapshot การตั้งค่ากลุ่มล่าสุด
  invites         ทะเบียนลิงก์เชิญที่เชื่อถือ + ประวัติ
  secret_findings ผลตรวจข้อมูลลับ — เก็บเฉพาะค่าที่ถูก redact แล้ว ไม่เคยเก็บของจริง
  se_findings     ผลตรวจ social engineering (ไม่เก็บเนื้อข้อความเต็มโดยไม่จำเป็น)
  incidents       เหตุการณ์ที่ correlate แล้ว
  backups         สำเนาการตั้งค่าที่บอตเข้าถึงได้
  audit_index     ดัชนี audit แบบ query เร็ว (ตัว tamper-evident จริงอยู่ที่ integrity_ledger)
  notif_state     สถานะกันแจ้งเตือนซ้ำ/throttle

หมายเหตุขอบเขต: โมดูลนี้ใช้เฉพาะข้อมูลที่ Telegram Bot API เปิดให้เท่านั้น
ไม่มีการอ้างว่าเห็น session/อุปกรณ์/IP/กิจกรรมบัญชีส่วนตัว
"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.gsi.store")

DB_PATH = os.getenv("GSI_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "resource", "group_security.json",
)

# เพดานกันไฟล์บวม (ปรับได้ด้วย env)
MAX_FINDINGS = int(os.getenv("GSI_MAX_FINDINGS", "500") or "500")
MAX_INCIDENTS = int(os.getenv("GSI_MAX_INCIDENTS", "300") or "300")
MAX_AUDIT_INDEX = int(os.getenv("GSI_MAX_AUDIT_INDEX", "1000") or "1000")
MAX_INVITE_HISTORY = int(os.getenv("GSI_MAX_INVITE_HISTORY", "300") or "300")
MAX_BACKUPS = int(os.getenv("GSI_MAX_BACKUPS", "30") or "30")


# นโยบายเริ่มต้นต่อกลุ่ม — ทุกค่าปรับได้ (ไม่มีการ hardcode admin id/secret)
DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": True,
    "notify": True,                 # ส่งแจ้งเตือนเข้า group ไหม
    "notify_min_severity": "MEDIUM",  # แจ้งเฉพาะ >= ระดับนี้
    "notify_throttle_sec": 300,     # เว้นระยะแจ้งเตือนชนิดเดียวกัน
    "snapshot_interval_sec": 3600,  # ความถี่ poll snapshot (Bot API ไม่ push ทุกอย่าง)
    "retention_days": 90,           # เก็บ finding/audit กี่วัน
    "secret_scan": True,            # ตรวจข้อมูลลับในข้อความ
    "social_eng_scan": True,        # ตรวจ social engineering
    "social_eng_use_ai": False,     # ใช้ AI ช่วยวิเคราะห์ SE (ต้องเปิดเอง + มี AI key)
    "correlation_window_sec": 900,  # หน้าต่าง correlate เหตุการณ์
    "correlation_min_events": 2,    # เหตุการณ์ขั้นต่ำจึงรวมเป็น incident
    "delete_detected_secrets": False,  # ลบข้อความที่พบ secret อัตโนมัติไหม (ต้องมีสิทธิ์ลบ)
}


# ---------------------------------------------------------------------------
# เวลา
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).isoformat()


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
        logger.error("GSI DB LOAD FAILED (%s) — starting empty", e)
        data = {}
    data.setdefault("chats", {})
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _db_path(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".gsi.", suffix=".tmp", dir=parent)
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
# โครงต่อ chat
# ---------------------------------------------------------------------------

def _blank_chat() -> Dict[str, Any]:
    return {
        "policy": dict(DEFAULT_POLICY),
        "admins": None,          # snapshot ล่าสุด {taken_iso, admins:[...]}
        "config": None,          # snapshot ล่าสุด {taken_iso, props:{...}}
        "invites": {"registry": {}, "history": [], "last_status": None},
        "secret_findings": [],
        "se_findings": [],
        "incidents": [],
        "audit_index": [],
        "backups": [],
        "notif_state": {},
        "seq": 0,                # ตัวนับ id ภายใน (incident/backup)
    }


def get_chat(db: Dict[str, Any], chat_id) -> Dict[str, Any]:
    chats = db.setdefault("chats", {})
    key = str(chat_id)
    node = chats.get(key)
    if node is None:
        node = _blank_chat()
        chats[key] = node
    # เติม field ที่อาจขาด (เผื่อสคีมาเก่า)
    base = _blank_chat()
    for k, v in base.items():
        node.setdefault(k, v)
    pol = dict(DEFAULT_POLICY)
    pol.update(node.get("policy", {}))
    node["policy"] = pol
    return node


def next_seq(node: Dict[str, Any]) -> int:
    node["seq"] = int(node.get("seq", 0)) + 1
    return node["seq"]


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------

def get_policy(chat_id, path: Optional[str] = None) -> Dict[str, Any]:
    return get_chat(load(path), chat_id)["policy"]


def set_policy(chat_id, key: str, value: Any, path: Optional[str] = None) -> Dict[str, Any]:
    if key not in DEFAULT_POLICY:
        raise ValueError(f"ไม่รู้จัก policy: {key!r}")
    db = load(path)
    node = get_chat(db, chat_id)
    node["policy"][key] = value
    save(db, path)
    return node["policy"]


def mutate_chat(chat_id, fn, path: Optional[str] = None):
    """load-modify-write ต่อ chat — fn(node) แก้ในที่ คืนค่าที่ fn คืน"""
    db = load(path)
    node = get_chat(db, chat_id)
    result = fn(node)
    save(db, path)
    return result


# ---------------------------------------------------------------------------
# append + prune helper
# ---------------------------------------------------------------------------

def _append_capped(lst: List[Any], item: Any, cap: int) -> None:
    lst.append(item)
    if len(lst) > cap:
        del lst[: len(lst) - cap]


def prune_retention(node: Dict[str, Any], now: Optional[datetime] = None) -> int:
    """ลบ finding/audit ที่เกิน retention_days — คืนจำนวนที่ลบ"""
    now = now or utcnow()
    days = int(node["policy"].get("retention_days", 90))
    if days <= 0:
        return 0
    cutoff = now.timestamp() - days * 86400
    removed = 0

    def _keep(lst):
        nonlocal removed
        kept = []
        for it in lst:
            ts = parse_iso(it.get("ts") or it.get("taken_iso") or it.get("created_iso"))
            if ts is None or ts.timestamp() >= cutoff:
                kept.append(it)
            else:
                removed += 1
        return kept

    node["secret_findings"] = _keep(node["secret_findings"])
    node["se_findings"] = _keep(node["se_findings"])
    node["audit_index"] = _keep(node["audit_index"])
    return removed


# ---------------------------------------------------------------------------
# accessor ย่อแบบอ่านอย่างเดียว (ใช้ในคำสั่ง)
# ---------------------------------------------------------------------------

def recent(node_list: List[Any], n: int = 10) -> List[Any]:
    return list(node_list[-n:][::-1])
