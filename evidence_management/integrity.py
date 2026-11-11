# -*- coding: utf-8 -*-
"""evidence_management/integrity.py — SHA-256 + chain-of-custody hash chain + verify (pure)

reuse ของแพลตฟอร์ม:
  integrity_ledger.canonical_json  — JSON determinisitc (hash reproducible)
  integrity_ledger.leaf_hash/node_hash/merkle_root — RFC 6962 Merkle (ของเดิม ไม่ทำซ้ำ)

chain of custody = hash chain เชิงเส้นแบบ append-only:
  event_hash = sha256(canonical(event ไม่รวม hash) + previous_event_hash)
เปลี่ยน/สลับเหตุการณ์ใด ๆ -> chain ขาดตั้งแต่จุดนั้น ตรวจจับได้

ข้อจำกัด (บันทึกตามสเปค): hash พิสูจน์ได้แค่ว่า "เนื้อหาเหมือนตอนบันทึก" — ไม่พิสูจน์ว่า
ใครเก็บ/เก็บเมื่อไร และ chain-of-custody record ไม่ได้ทำให้รับฟังได้ตามกฎหมายโดยอัตโนมัติ
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from integrity_ledger import canonical_json as _canonical_json, \
        leaf_hash as _leaf_hash, node_hash as _node_hash, merkle_root as _merkle_root
    _HAS_LEDGER = True
except Exception:  # pragma: no cover
    _HAS_LEDGER = False

    def _canonical_json(payload) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

HASH_ALGORITHM = "SHA-256"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# content hashing
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_content(content: Any) -> Tuple[Optional[str], Optional[int]]:
    """คืน (sha256_hex, size_bytes) ของเนื้อหา evidence

    content เป็น bytes -> hash ตรง; เป็น str/dict/list -> canonical JSON/utf-8 ก่อน
    None -> (None, None) (evidence เชิง metadata ล้วน ไม่มี artifact)
    """
    if content is None:
        return None, None
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raw = _canonical_json(content).encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), len(raw)


# ---------------------------------------------------------------------------
# chain of custody (hash chain)
# ---------------------------------------------------------------------------

def _event_core(event: Dict[str, Any]) -> Dict[str, Any]:
    """ส่วนของ event ที่เข้าสู่ hash (ไม่รวม event_hash เอง)"""
    return {k: event[k] for k in event if k != "event_hash"}


def compute_event_hash(event: Dict[str, Any], previous_event_hash: str) -> str:
    material = (_canonical_json(_event_core(event)) + "|" + (previous_event_hash or "")).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def make_custody_event(event_id: str, evidence_id: str, event_type: str, actor: str,
                       action: str, previous_event_hash: Optional[str],
                       metadata: Optional[Dict[str, Any]] = None,
                       timestamp: Optional[str] = None) -> Dict[str, Any]:
    """สร้าง custody event พร้อมคำนวณ event_hash ที่ผูกกับ previous_event_hash"""
    event = {
        "event_id": event_id,
        "evidence_id": evidence_id,
        "event_type": event_type,
        "actor": str(actor),
        "action": action,
        "timestamp": timestamp or _now_iso(),
        "previous_event_hash": previous_event_hash,
        "metadata": metadata or {},
    }
    event["event_hash"] = compute_event_hash(event, previous_event_hash or "")
    return event


def verify_custody_chain(custody: List[Dict[str, Any]]) -> Dict[str, Any]:
    """ตรวจ hash chain ของ custody — คืน {ok, length, broken_at, merkle_root}"""
    prev = ""
    broken_at = None
    for i, ev in enumerate(custody or []):
        expected = compute_event_hash(ev, prev)
        if ev.get("event_hash") != expected:
            broken_at = i
            break
        if ev.get("previous_event_hash") not in (prev, prev or None):
            broken_at = i
            break
        prev = ev["event_hash"]
    root = merkle_root_of(custody) if not broken_at and custody else None
    return {"ok": broken_at is None, "length": len(custody or []),
            "broken_at": broken_at, "merkle_root": root}


def merkle_root_of(custody: List[Dict[str, Any]]) -> Optional[str]:
    """Merkle root ของ custody events (reuse integrity_ledger RFC6962) — หรือ None"""
    if not custody:
        return None
    leaves = [_canonical_json(_event_core(ev)).encode("utf-8") for ev in custody]
    if not _HAS_LEDGER:
        # fallback: โยง hash ต่อกันแล้ว sha256 (ยังตรวจการเปลี่ยนได้ แม้ไม่ใช่ RFC6962)
        h = hashlib.sha256()
        for lf in leaves:
            h.update(hashlib.sha256(lf).digest())
        return h.hexdigest()
    return _merkle_root(leaves).hex()


# ---------------------------------------------------------------------------
# verification (ไม่แก้ไข evidence เดิม)
# ---------------------------------------------------------------------------

def verify_record(record: Dict[str, Any], *, content: Any = None,
                  artifact_exists: Optional[bool] = None,
                  artifact_readable: Optional[bool] = None) -> Dict[str, Any]:
    """ตรวจ evidence หนึ่งรายการ — คืนผลแบบมีโครงสร้าง (ไม่แก้ record)

    content: ถ้าให้มา จะ recompute hash เทียบกับ content_hash เดิม (tamper detection)
    artifact_exists/readable: ผลที่ caller ตรวจไฟล์มา (store ไม่สมมติว่าสำเร็จ)
    """
    issues: List[str] = []
    stored = record.get("content_hash")
    hash_match = None
    current_hash = None
    if content is not None and stored:
        current_hash, _ = hash_content(content)
        hash_match = (current_hash == stored)
        if not hash_match:
            issues.append("HASH_MISMATCH")
    elif content is not None and not stored:
        issues.append("NO_STORED_HASH")

    if artifact_exists is False:
        issues.append("ARTIFACT_MISSING")
    if artifact_readable is False:
        issues.append("ARTIFACT_UNREADABLE")

    # custody chain
    chain = verify_custody_chain(record.get("custody", []))
    if not chain["ok"]:
        issues.append(f"CUSTODY_CHAIN_BROKEN_AT_{chain['broken_at']}")

    # metadata sanity
    if not record.get("evidence_id") or not record.get("assessment_id"):
        issues.append("METADATA_INCOMPLETE")

    passed = not issues
    return {
        "evidence_id": record.get("evidence_id"),
        "verification_result": "passed" if passed else "failed",
        "hash_match": hash_match,
        "stored_hash": stored,
        "current_hash": current_hash,
        "artifact_exists": artifact_exists,
        "metadata_valid": bool(record.get("evidence_id") and record.get("assessment_id")),
        "custody_chain_ok": chain["ok"],
        "custody_merkle_root": chain["merkle_root"],
        "verified_at": _now_iso(),
        "issues": issues,
    }


INTEGRITY_LIMITS_NOTE = (
    "hash พิสูจน์ได้แค่ 'เนื้อหาเหมือนตอนบันทึก' ไม่พิสูจน์ผู้เก็บ/เวลาเก็บจริง · "
    "chain-of-custody ไม่ได้ทำให้รับฟังตามกฎหมายโดยอัตโนมัติ"
)
