# -*- coding: utf-8 -*-
"""api_security_assessment/store.py — เก็บ assessment + imported spec (atomic JSON)"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.api.store")

DB_PATH = os.getenv("API_ASSESS_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resource", "api_assess.json")

MAX_ASSESSMENTS = int(os.getenv("API_MAX_ASSESSMENTS", "300") or "300")

DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": True,
    "categories": ["authentication", "authorization", "input_validation", "sqli",
                   "xss", "graphql", "cors", "info_disclosure", "misconfiguration"],
    "max_requests": 60,
    "max_endpoints": 80,
    "param_name": "q",
    "notify_min_severity": "HIGH",
    "allow_state_changing": False,   # PUT/PATCH/DELETE เฉพาะเมื่อเปิด (staging + disposable)
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
        logger.error("API DB LOAD FAILED (%s)", e)
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("assessments", {})
    data.setdefault("specs", {})      # domain -> {endpoints, api_info, imported_iso}
    pol = dict(DEFAULT_POLICY)
    pol.update(data.get("policy", {}) if isinstance(data.get("policy"), dict) else {})
    data["policy"] = pol
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _p(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".api.", suffix=".tmp", dir=parent)
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


# ---- imported specs ----

def store_spec(domain: str, endpoints: List[Dict[str, Any]], api_info: Dict[str, Any],
               kind: str, path: Optional[str] = None) -> None:
    db = load(path)
    db["specs"][domain] = {"endpoints": endpoints, "api_info": api_info, "kind": kind,
                           "imported_iso": iso()}
    save(db, path)


def get_spec(domain: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["specs"].get(domain)


# ---- assessments ----

def create_assessment(program_id: int, target: str, actor: int, categories: List[str],
                      path: Optional[str] = None) -> Dict[str, Any]:
    db = load(path)
    db["seq"] = int(db.get("seq", 0)) + 1
    aid = db["seq"]
    rec = {"id": aid, "program_id": program_id, "target": target, "actor": actor,
           "categories": categories, "status": "created", "denied_reason": None,
           "cancel": False, "created_iso": iso(), "finished_iso": None,
           "endpoints_analyzed": 0, "checks_executed": 0, "requests_made": 0,
           "findings": [], "endpoint_summary": {}, "errors": [], "counts": {}}
    db["assessments"][str(aid)] = rec
    if len(db["assessments"]) > MAX_ASSESSMENTS:
        oldest = sorted(db["assessments"].values(), key=lambda s: s["id"])[
            : len(db["assessments"]) - MAX_ASSESSMENTS]
        for o in oldest:
            db["assessments"].pop(str(o["id"]), None)
    save(db, path)
    return rec


def update_assessment(aid: int, fn, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    db = load(path)
    rec = db["assessments"].get(str(aid))
    if rec is None:
        return None
    fn(rec)
    save(db, path)
    return rec


def get_assessment(aid: int, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["assessments"].get(str(aid))


def is_cancelled(aid: int, path: Optional[str] = None) -> bool:
    r = get_assessment(aid, path)
    return bool(r and r.get("cancel"))


def request_cancel(aid: int, path: Optional[str] = None) -> bool:
    return update_assessment(aid, lambda r: r.__setitem__("cancel", True), path) is not None


def list_assessments(program_id: Optional[int] = None, limit: int = 20,
                     path: Optional[str] = None) -> List[Dict[str, Any]]:
    a = list(load(path)["assessments"].values())
    if program_id is not None:
        a = [x for x in a if x.get("program_id") == program_id]
    a.sort(key=lambda x: x["id"], reverse=True)
    return a[:limit]
