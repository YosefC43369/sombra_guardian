# -*- coding: utf-8 -*-
"""risk_prioritization/store.py — เก็บผลการจัดลำดับความเสี่ยง (atomic JSON, pattern เดิม)"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import model

logger = logging.getLogger("modbot.risk.store")

DB_PATH = os.getenv("RISK_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resource",
    "risk_prioritization.json")

MAX_RESULTS = int(os.getenv("RISK_MAX_RESULTS", "200") or "200")


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


DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": _env_bool("RISK_ENGINE_ENABLED", True),
    "model_version": int(os.getenv("RISK_MODEL_VERSION", str(model.MODEL_VERSION))
                         or model.MODEL_VERSION),
    "confidence_threshold": _env_float("RISK_CONFIDENCE_THRESHOLD", 0.70),
    "weights": dict(model.DEFAULT_WEIGHTS),
    "use_ai": _env_bool("RISK_AI_ANALYSIS_ENABLED", False),
}


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


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
        logger.error("RISK DB LOAD FAILED (%s)", e)
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("results", {})
    data.setdefault("latest_by_target", {})
    pol = dict(DEFAULT_POLICY)
    pol.update(data.get("policy", {}) if isinstance(data.get("policy"), dict) else {})
    data["policy"] = pol
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _p(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".risk.", suffix=".tmp", dir=parent)
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
    return f"RISK-{datetime.now(timezone.utc).year}-{seq:06d}"


def save_result(result: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    db = load(path)
    db["seq"] = int(db.get("seq", 0)) + 1
    rid = make_result_id(db["seq"])
    result = dict(result)
    result["result_id"] = rid
    result["seq"] = db["seq"]
    result.setdefault("created_iso", iso())
    db["results"][rid] = result
    if result.get("target"):
        db["latest_by_target"][result["target"]] = rid
    if len(db["results"]) > MAX_RESULTS:
        keep = set(db["latest_by_target"].values())
        for o in sorted(db["results"].values(), key=lambda r: r.get("seq", 0)):
            if len(db["results"]) <= MAX_RESULTS:
                break
            if o["result_id"] not in keep:
                db["results"].pop(o["result_id"], None)
    save(db, path)
    return result


def get_result(result_id: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["results"].get(result_id)


def latest_for_target(target: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    db = load(path)
    rid = db["latest_by_target"].get(target)
    return db["results"].get(rid) if rid else None


def list_results(limit: int = 20, path: Optional[str] = None) -> List[Dict[str, Any]]:
    rs = list(load(path)["results"].values())
    rs.sort(key=lambda r: r.get("seq", 0), reverse=True)
    return rs[:limit]
