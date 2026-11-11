# -*- coding: utf-8 -*-
"""evidence_management/store.py — เก็บ evidence record + custody (atomic JSON, append-only)

แนวทางเดียวกับทุกโมดูล (atomic temp+os.replace+fsync) — reuse pattern เดิม
เก็บ: evidence records (ดัชนีตาม assessment/finding/asset/module/type) + custody chain
ต่อ record + integrity history (ไม่เขียนทับของเดิมเงียบ ๆ)

ไม่เก็บ secret/token — ทุก evidence ถูก redact มาก่อนจาก redact.py; artifact bytes ไม่เก็บ
ในนี้ (เก็บ storage_reference + hash) เว้นแต่ถูกส่ง inline ให้ hash เท่านั้น
"""

from __future__ import annotations

import os
import json
import tempfile
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import schema, integrity

logger = logging.getLogger("modbot.evidence.store")

DB_PATH = os.getenv("EVIDENCE_DB", "").strip() or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resource",
    "evidence_management.json")

MAX_RECORDS = int(os.getenv("EVIDENCE_MAX_RECORDS", "5000") or "5000")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() not in ("false", "0", "no", "off")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default


DEFAULT_POLICY: Dict[str, Any] = {
    "enabled": _env_bool("EVIDENCE_MANAGEMENT_ENABLED", True),
    "hash_algorithm": (os.getenv("EVIDENCE_HASH_ALGORITHM", "sha256") or "sha256").lower(),
    "max_file_size_mb": max(1, _env_int("EVIDENCE_MAX_FILE_SIZE_MB", 25)),
    "verify_on_ingest": _env_bool("EVIDENCE_VERIFY_ON_INGEST", True),
    "audit_trail_enabled": _env_bool("EVIDENCE_AUDIT_TRAIL_ENABLED", True),
    "redaction_enabled": _env_bool("EVIDENCE_REDACTION_ENABLED", True),
    "retention_days": _env_int("EVIDENCE_RETENTION_DAYS", 365),
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
        logger.error("EVIDENCE DB LOAD FAILED (%s)", e)
        data = {}
    data.setdefault("seq", 0)
    data.setdefault("custody_seq", 0)
    data.setdefault("evidence", {})          # evidence_id -> record
    pol = dict(DEFAULT_POLICY)
    pol.update(data.get("policy", {}) if isinstance(data.get("policy"), dict) else {})
    data["policy"] = pol
    return data


def save(db: Dict[str, Any], path: Optional[str] = None) -> None:
    target = _p(path)
    parent = os.path.dirname(target) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".evd.", suffix=".tmp", dir=parent)
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


# ---------------------------------------------------------------------------
# evidence records
# ---------------------------------------------------------------------------

def _next_custody_id(db: Dict[str, Any]) -> str:
    db["custody_seq"] = int(db.get("custody_seq", 0)) + 1
    return schema.make_custody_id(db["custody_seq"])


def _append_custody(db: Dict[str, Any], rec: Dict[str, Any], event_type: str,
                    actor: str, action: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    prev = rec["custody"][-1]["event_hash"] if rec.get("custody") else None
    ev = integrity.make_custody_event(_next_custody_id(db), rec["evidence_id"],
                                      event_type, actor, action, prev, metadata)
    rec["custody"].append(ev)
    return ev


def create_record(record: Dict[str, Any], actor: str = "assessment_module", *,
                  initial_events: Optional[List[tuple]] = None,
                  path: Optional[str] = None) -> Dict[str, Any]:
    """เก็บ evidence record ใหม่ + ลง custody เริ่มต้น (created/collected/validated/stored)"""
    db = load(path)
    db["seq"] = int(db.get("seq", 0)) + 1
    record = dict(record)
    record["evidence_id"] = schema.make_evidence_id(db["seq"])
    record["seq"] = db["seq"]
    record.setdefault("custody", [])
    events = initial_events or [
        ("evidence_created", "Evidence record created"),
        ("evidence_collected", "Evidence received from assessment module"),
        ("evidence_validated", "Structure and references validated"),
        ("evidence_stored", "Evidence metadata stored"),
    ]
    for et, action in events:
        _append_custody(db, record, et, actor, action)
    db["evidence"][record["evidence_id"]] = record
    _enforce_retention(db)
    save(db, path)
    return record


def _enforce_retention(db: Dict[str, Any]) -> None:
    if len(db["evidence"]) <= MAX_RECORDS:
        return
    olds = sorted(db["evidence"].values(), key=lambda r: r.get("seq", 0))
    for o in olds:
        if len(db["evidence"]) <= MAX_RECORDS:
            break
        db["evidence"].pop(o["evidence_id"], None)


def get_record(evidence_id: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return load(path)["evidence"].get(evidence_id)


def add_custody_event(evidence_id: str, event_type: str, actor: str, action: str,
                      metadata: Optional[Dict[str, Any]] = None,
                      path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """เพิ่ม custody event (append-only) — เช่น accessed/exported/integrity_verified"""
    if event_type not in schema.CUSTODY_EVENTS:
        raise ValueError(f"INVALID_CUSTODY_EVENT:{event_type}")
    db = load(path)
    rec = db["evidence"].get(evidence_id)
    if rec is None:
        return None
    ev = _append_custody(db, rec, event_type, actor, action, metadata)
    save(db, path)
    return ev


def mark_integrity(evidence_id: str, status: str, actor: str, detail: str,
                   path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """อัปเดต integrity_status + เก็บประวัติเดิม (ไม่เขียนทับเงียบ) + custody event"""
    if status not in schema.INTEGRITY_STATES:
        raise ValueError(f"INVALID_INTEGRITY_STATUS:{status}")
    db = load(path)
    rec = db["evidence"].get(evidence_id)
    if rec is None:
        return None
    prev = rec.get("integrity_status")
    rec.setdefault("integrity_history", []).append(
        {"from": prev, "to": status, "detail": detail[:300], "at": iso()})
    rec["integrity_status"] = status
    et = "evidence_marked_suspicious" if status == "compromised" else "evidence_integrity_verified"
    _append_custody(db, rec, et, actor, detail[:200], {"integrity_status": status})
    save(db, path)
    return rec


# ---------------------------------------------------------------------------
# search / retrieval
# ---------------------------------------------------------------------------

def search(*, assessment_id: Optional[str] = None, finding_id: Optional[str] = None,
           asset_id: Optional[str] = None, source_module: Optional[str] = None,
           evidence_type: Optional[str] = None, integrity_status: Optional[str] = None,
           verification_status: Optional[str] = None, text: Optional[str] = None,
           collected_after: Optional[str] = None, collected_before: Optional[str] = None,
           limit: int = 100, path: Optional[str] = None) -> List[Dict[str, Any]]:
    """ค้น evidence ตามตัวกรองหลายแกน (ใช้ดัชนีในหน่วยความจำ — ชุดข้อมูลระดับโมดูล)"""
    recs = list(load(path)["evidence"].values())

    def _keep(r: Dict[str, Any]) -> bool:
        if assessment_id and r.get("assessment_id") != assessment_id:
            return False
        if finding_id and finding_id not in (r.get("finding_ids") or []):
            return False
        if asset_id and asset_id not in (r.get("asset_ids") or []):
            return False
        if source_module and r.get("source_module") != source_module:
            return False
        if evidence_type and r.get("evidence_type") != evidence_type:
            return False
        if integrity_status and r.get("integrity_status") != integrity_status:
            return False
        if verification_status and r.get("verification_status") != verification_status:
            return False
        if collected_after and (r.get("collected_at") or "") < collected_after:
            return False
        if collected_before and (r.get("collected_at") or "~") > collected_before:
            return False
        if text:
            hay = (r.get("title", "") + " " + r.get("description", "") + " " +
                   json.dumps(r.get("metadata", {}), ensure_ascii=False)).lower()
            if text.lower() not in hay:
                return False
        return True

    out = [r for r in recs if _keep(r)]
    out.sort(key=lambda r: r.get("seq", 0), reverse=True)
    return out[:limit]


def by_assessment(assessment_id: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
    return search(assessment_id=assessment_id, limit=10000, path=path)


def by_finding(finding_id: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
    return search(finding_id=finding_id, limit=10000, path=path)


def list_assessments(path: Optional[str] = None) -> List[str]:
    return sorted({r.get("assessment_id") for r in load(path)["evidence"].values()
                   if r.get("assessment_id")})
