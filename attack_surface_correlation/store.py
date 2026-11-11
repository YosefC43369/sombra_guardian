# -*- coding: utf-8 -*-
"""attack_surface_correlation/store.py — เก็บผล correlation + snapshot ประวัติ (atomic JSON)

แนวทางเดียวกับทุกโมดูลในโปรเจกต์ (atomic temp+os.replace+fsync) — reuse ไม่ใช่ของใหม่
เก็บ: correlation result ต่อ run + ดัชนี snapshot ล่าสุดต่อ target (ไว้เทียบประวัติ)

ไม่เก็บ secret/token — asset/evidence ถูก sanitize/บีบมาก่อนแล้ว และไม่เก็บ response body
"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.asc.store")

DB_PATH = os.getenv("ASC_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resource",
    "attack_surface_correlation.json")

MAX_RESULTS = int(os.getenv("ASC_MAX_RESULTS", "200") or "200")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() not in ("false", "0", "no", "off")


def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.getenv(name, "") or default)
        return v if 0.0 <= v <= 1.0 else default
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default


# policy อ่านจาก env เดิม (reuse) — validate ค่าเสมอ
DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": _env_bool("ATTACK_SURFACE_CORRELATION_ENABLED", True),
    "confidence_threshold": _env_float("CORRELATION_CONFIDENCE_THRESHOLD", 0.70),
    "max_assets": max(1, _env_int("CORRELATION_MAX_ASSETS", 10000)),
    "history_enabled": _env_bool("CORRELATION_HISTORY_ENABLED", True),
    "use_ai": _env_bool("CORRELATION_AI_ANALYSIS_ENABLED", False),
    "retention_days": 90,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).isoformat()


def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s or not isinstance(s, str):
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


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
        logger.error("ASC DB LOAD FAILED (%s)", e)
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("results", {})            # result_id -> correlation result
    data.setdefault("latest_by_target", {})   # target -> result_id (ไว้เทียบประวัติ)
    pol = dict(DEFAULT_POLICY)
    pol.update(data.get("policy", {}) if isinstance(data.get("policy"), dict) else {})
    data["policy"] = pol
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _p(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".asc.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2, default=str)
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


def make_result_id(seq: int) -> str:
    return f"ASC-{datetime.now(timezone.utc).year}-{seq:06d}"


def save_result(result: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    """เก็บ correlation result + อัปเดตดัชนี latest ต่อ target คืน result ที่มี result_id"""
    db = load(path)
    db["seq"] = int(db.get("seq", 0)) + 1
    rid = make_result_id(db["seq"])
    result = dict(result)
    result["result_id"] = rid
    result["seq"] = db["seq"]
    result.setdefault("created_iso", iso())
    db["results"][rid] = result
    tgt = result.get("target")
    if tgt:
        db["latest_by_target"][tgt] = rid
    # retention (เก็บไม่เกิน MAX_RESULTS — ลบเฉพาะ result เก่าสุด ไม่ลบ index เป้าหมายล่าสุด)
    if len(db["results"]) > MAX_RESULTS:
        keep_ids = set(db["latest_by_target"].values())
        olds = sorted(db["results"].values(), key=lambda r: r.get("seq", 0))
        for o in olds:
            if len(db["results"]) <= MAX_RESULTS:
                break
            if o["result_id"] in keep_ids:
                continue
            db["results"].pop(o["result_id"], None)
    save(db, path)
    return result


def get_result(result_id: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["results"].get(result_id)


def latest_for_target(target: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    db = load(path)
    rid = db["latest_by_target"].get(target)
    return db["results"].get(rid) if rid else None


def list_results(limit: int = 20, target: Optional[str] = None,
                 path: Optional[str] = None) -> List[Dict[str, Any]]:
    rs = list(load(path)["results"].values())
    if target is not None:
        rs = [r for r in rs if r.get("target") == target]
    rs.sort(key=lambda r: r.get("seq", 0), reverse=True)
    return rs[:limit]
