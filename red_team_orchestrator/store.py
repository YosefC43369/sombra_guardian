# -*- coding: utf-8 -*-
"""red_team_orchestrator/store.py — เก็บ task ของออร์เคสเตรเตอร์ (atomic JSON)

เก็บ task + execution plan + module results + audit trail แยกตาม task id
แนวทางเดียวกับโมดูลอื่นในโปรเจกต์ (atomic temp+os.replace+fsync)

ไม่เก็บ secret/token ใด ๆ (evidence ถูก sanitize มาก่อนแล้วจาก classify)
"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.rt_orch.store")

DB_PATH = os.getenv("RT_ORCH_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resource", "rt_orchestrator.json")

MAX_TASKS = int(os.getenv("RT_ORCH_MAX_TASKS", "300") or "300")

# สถานะ task (ตามสเปค)
STATES = ("PENDING", "VALIDATING", "AWAITING_APPROVAL", "RUNNING",
          "PARTIALLY_COMPLETED", "COMPLETED", "FAILED", "CANCELLED")

DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": True,
    "max_concurrent_tasks": int(os.getenv("ORCHESTRATOR_MAX_CONCURRENT_TASKS", "2") or "2"),
    "module_timeout": int(os.getenv("ORCHESTRATOR_MODULE_TIMEOUT", "900") or "900"),
    "require_approval": (os.getenv("ORCHESTRATOR_REQUIRE_APPROVAL", "true").lower() != "false"),
    "retry_limit": int(os.getenv("ORCHESTRATOR_RETRY_LIMIT", "2") or "2"),
    "retention_days": 90,
    "use_ai": False,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).isoformat()


def _p(p): return p or DB_PATH


def load(path: Optional[str] = None) -> Dict[str, Any]:
    try:
        with open(_p(path), "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError
    except FileNotFoundError:
        data = {}
    except (json.JSONDecodeError, ValueError, OSError) as e:
        logger.error("RT_ORCH DB LOAD FAILED (%s)", e)
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("tasks", {})
    pol = dict(DEFAULT_POLICY)
    pol.update(data.get("policy", {}) if isinstance(data.get("policy"), dict) else {})
    data["policy"] = pol
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _p(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".rtorch.", suffix=".tmp", dir=parent)
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


# ---------------------------------------------------------------------------
# tasks
# ---------------------------------------------------------------------------

def make_task_id(seq: int) -> str:
    return f"RT-{datetime.now(timezone.utc).year}-{seq:06d}"


def create_task(task_type: str, target: str, actor: int, chat_id: int,
                options: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    db = load(path)
    db["seq"] = int(db.get("seq", 0)) + 1
    tid = make_task_id(db["seq"])
    rec = {
        "task_id": tid, "seq": db["seq"], "task_type": task_type, "target": target,
        "actor": actor, "chat_id": chat_id, "options": _redact_options(options),
        "status": "PENDING", "status_reason": None,
        "plan": {}, "module_results": [], "findings": [], "ai_summary": None,
        "cancel": False, "counts": {}, "audit": [],
        "created_iso": iso(), "started_iso": None, "finished_iso": None,
    }
    db["tasks"][tid] = rec
    if len(db["tasks"]) > MAX_TASKS:
        oldest = sorted(db["tasks"].values(), key=lambda t: t["seq"])[: len(db["tasks"]) - MAX_TASKS]
        for o in oldest:
            db["tasks"].pop(o["task_id"], None)
    save(db, path)
    return rec


def _redact_options(options: Dict[str, Any]) -> Dict[str, Any]:
    """ไม่เก็บ token/secret ใน task record"""
    out = {}
    for k, v in (options or {}).items():
        if k in ("token", "token_a", "token_b") or "token" in k.lower() or "secret" in k.lower():
            out[k] = "[REDACTED]" if v else None
        else:
            out[k] = v
    return out


def update_task(task_id: str, fn, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    db = load(path)
    rec = db["tasks"].get(task_id)
    if rec is None:
        return None
    fn(rec)
    save(db, path)
    return rec


def get_task(task_id: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["tasks"].get(task_id)


def is_cancelled(task_id: str, path: Optional[str] = None) -> bool:
    r = get_task(task_id, path)
    return bool(r and r.get("cancel"))


def request_cancel(task_id: str, path: Optional[str] = None) -> bool:
    return update_task(task_id, lambda r: r.__setitem__("cancel", True), path) is not None


def list_tasks(limit: int = 20, actor: Optional[int] = None,
               path: Optional[str] = None) -> List[Dict[str, Any]]:
    t = list(load(path)["tasks"].values())
    if actor is not None:
        t = [x for x in t if x.get("actor") == actor]
    t.sort(key=lambda x: x["seq"], reverse=True)
    return t[:limit]


def running_count(path: Optional[str] = None) -> int:
    return sum(1 for t in load(path)["tasks"].values() if t["status"] == "RUNNING")


def active_task_for(task_type: str, target: str, path: Optional[str] = None
                    ) -> Optional[Dict[str, Any]]:
    """หา task ที่ยัง active (ไม่จบ) ของ (type,target) เดียวกัน — กันรันซ้ำ"""
    for t in load(path)["tasks"].values():
        if (t["task_type"] == task_type and t["target"] == target
                and t["status"] in ("PENDING", "VALIDATING", "AWAITING_APPROVAL", "RUNNING")):
            return t
    return None


def audit(task_id: str, event: str, detail: str = "", path: Optional[str] = None) -> None:
    def _mut(r):
        r["audit"].append({"ts": iso(), "event": event, "detail": detail[:300]})
    update_task(task_id, _mut, path)
