# -*- coding: utf-8 -*-
"""active_scan/store.py — ชั้นเก็บผลสแกนแบบ active (atomic JSON)

เก็บผลการสแกนแยกตาม program (scope_policy) และ scan id ในไฟล์ JSON เดียว
เขียน atomic (temp + os.replace + fsync) — แนวทางเดียวกับโมดูลอื่นในโปรเจกต์

สคีมา:
{
  "seq": 3,
  "scans": {
    "<id>": {
      "id": 1, "program_id": 10, "target": "example.com", "profile": "top100",
      "status": "completed|running|denied|failed", "denied_reason": null,
      "actor": 123, "created_iso": "...", "finished_iso": "...",
      "hosts": [ {ip, hostname, ports:[{port,state,service,banner,latency_ms}]} ],
      "summary": {open_ports, hosts_up, ...},
      "dns": {...}, "web": [...], "errors": [...]
    }
  },
  "policy": { ... }   # เกณฑ์ปรับได้ (ไม่ hardcode)
}

หมายเหตุ: ไม่เก็บ credential/secret ใด ๆ — เก็บเฉพาะผล observe (port/banner/service)
"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.active_scan.store")

DB_PATH = os.getenv("ACTIVE_SCAN_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "resource", "active_scan.json",
)

MAX_SCANS = int(os.getenv("ASCAN_MAX_SCANS", "500") or "500")

# เกณฑ์เริ่มต้น — ปรับได้ด้วย policy (ไม่ hardcode)
DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": True,
    "concurrency": 100,          # จำนวน socket พร้อมกันต่อสแกน
    "connect_timeout": 2.0,      # timeout ต่อ connect (วินาที)
    "banner_timeout": 2.0,       # timeout อ่าน banner
    "rate_per_sec": 200.0,       # เพดานอัตรา connect รวม
    "max_ports_per_host": 1024,  # กันสแกนพอร์ตเกินควรต่อ host
    "max_hosts_per_scan": 256,   # กันขยาย CIDR ใหญ่เกิน (เช่น /24)
    "max_total_connects": 65536, # เพดาน (hosts * ports) ต่อสแกน
    "dns_axfr": True,            # ลอง zone transfer (AXFR) ไหม
    "web_probe": True,           # ตรวจ path เว็บแบบ bounded ไหม
}


# ---------------------------------------------------------------------------
# เวลา
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).isoformat()


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
            raise ValueError("root not an object")
    except FileNotFoundError:
        data = {}
    except (json.JSONDecodeError, ValueError, OSError) as e:
        logger.error("ASCAN DB LOAD FAILED (%s) — starting empty", e)
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("scans", {})
    pol = dict(DEFAULT_POLICY)
    pol.update(data.get("policy", {}) if isinstance(data.get("policy"), dict) else {})
    data["policy"] = pol
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _db_path(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ascan.", suffix=".tmp", dir=parent)
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
# policy
# ---------------------------------------------------------------------------

def get_policy(path: Optional[str] = None) -> Dict[str, Any]:
    return load(path)["policy"]


def set_policy(key: str, value: Any, path: Optional[str] = None) -> Dict[str, Any]:
    if key not in DEFAULT_POLICY:
        raise ValueError(f"ไม่รู้จัก policy: {key!r}")
    db = load(path)
    db["policy"][key] = value
    save(db, path)
    return db["policy"]


# ---------------------------------------------------------------------------
# scans
# ---------------------------------------------------------------------------

def create_scan(program_id: int, target: str, profile: str, actor: int,
                path: Optional[str] = None) -> Dict[str, Any]:
    db = load(path)
    db["seq"] = int(db.get("seq", 0)) + 1
    sid = db["seq"]
    rec = {
        "id": sid, "program_id": program_id, "target": target, "profile": profile,
        "status": "created", "denied_reason": None, "actor": actor,
        "created_iso": iso(), "finished_iso": None,
        "hosts": [], "summary": {}, "dns": {}, "web": [], "errors": [],
    }
    db["scans"][str(sid)] = rec
    # prune
    if len(db["scans"]) > MAX_SCANS:
        oldest = sorted(db["scans"].values(), key=lambda s: s["id"])[: len(db["scans"]) - MAX_SCANS]
        for o in oldest:
            db["scans"].pop(str(o["id"]), None)
    save(db, path)
    return rec


def update_scan(scan_id: int, fn, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    db = load(path)
    rec = db["scans"].get(str(scan_id))
    if rec is None:
        return None
    fn(rec)
    save(db, path)
    return rec


def get_scan(scan_id: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["scans"].get(str(scan_id))


def list_scans(program_id: Optional[int] = None, limit: int = 20,
               path: Optional[str] = None) -> List[Dict[str, Any]]:
    scans = list(load(path)["scans"].values())
    if program_id is not None:
        scans = [s for s in scans if s.get("program_id") == program_id]
    scans.sort(key=lambda s: s["id"], reverse=True)
    return scans[:limit]
