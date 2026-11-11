# -*- coding: utf-8 -*-
"""vuln_probe/store.py — เก็บผลการ probe (atomic JSON) — แนวทางเดียวกับโมดูลอื่น"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.vuln_probe.store")

DB_PATH = os.getenv("VULN_PROBE_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "resource", "vuln_probe.json",
)
MAX_RUNS = int(os.getenv("VPROBE_MAX_RUNS", "500") or "500")

DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": True,
    "param_name": "q",                 # พารามิเตอร์ทดสอบ (reflection/sqli/ssti)
    "redirect_params": ["next", "url", "redirect", "return", "dest"],
    "injected_host": "oob.sombra-probe.invalid",  # โฮสต์ marker สำหรับ open-redirect
    "max_requests": 12,                # เพดานคำขอรวมต่อ run (กันยิงถี่)
    "checks": ["reflection", "sqli", "ssti", "open_redirect", "cors", "takeover"],
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).isoformat()


def _db_path(path): return path or DB_PATH


def load(path: Optional[str] = None) -> Dict[str, Any]:
    try:
        with open(_db_path(path), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("root not object")
    except FileNotFoundError:
        data = {}
    except (json.JSONDecodeError, ValueError, OSError) as e:
        logger.error("VPROBE DB LOAD FAILED (%s)", e)
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("runs", {})
    pol = dict(DEFAULT_POLICY)
    pol.update(data.get("policy", {}) if isinstance(data.get("policy"), dict) else {})
    data["policy"] = pol
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _db_path(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".vprobe.", suffix=".tmp", dir=parent)
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


def get_policy(path: Optional[str] = None) -> Dict[str, Any]:
    return load(path)["policy"]


def set_policy(key: str, value: Any, path: Optional[str] = None) -> Dict[str, Any]:
    if key not in DEFAULT_POLICY:
        raise ValueError(f"ไม่รู้จัก policy: {key!r}")
    db = load(path)
    db["policy"][key] = value
    save(db, path)
    return db["policy"]


def create_run(program_id: int, target: str, actor: int,
               path: Optional[str] = None) -> Dict[str, Any]:
    db = load(path)
    db["seq"] = int(db.get("seq", 0)) + 1
    rid = db["seq"]
    rec = {"id": rid, "program_id": program_id, "target": target, "actor": actor,
           "status": "created", "denied_reason": None, "created_iso": iso(),
           "finished_iso": None, "indicators": [], "requests_made": 0, "errors": []}
    db["runs"][str(rid)] = rec
    if len(db["runs"]) > MAX_RUNS:
        oldest = sorted(db["runs"].values(), key=lambda s: s["id"])[: len(db["runs"]) - MAX_RUNS]
        for o in oldest:
            db["runs"].pop(str(o["id"]), None)
    save(db, path)
    return rec


def update_run(run_id: int, fn, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    db = load(path)
    rec = db["runs"].get(str(run_id))
    if rec is None:
        return None
    fn(rec)
    save(db, path)
    return rec


def get_run(run_id: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["runs"].get(str(run_id))


def list_runs(program_id: Optional[int] = None, limit: int = 20,
              path: Optional[str] = None) -> List[Dict[str, Any]]:
    runs = list(load(path)["runs"].values())
    if program_id is not None:
        runs = [r for r in runs if r.get("program_id") == program_id]
    runs.sort(key=lambda r: r["id"], reverse=True)
    return runs[:limit]
