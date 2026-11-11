# -*- coding: utf-8 -*-
"""evidence_management/schema.py — unified evidence schema + validation (pure)

นิยาม "evidence record" กลางของแพลตฟอร์ม + ชนิด/สถานะ + ตัวตรวจความถูกต้อง + สร้าง id
ล้วน (stdlib) จึงเทสต์ได้ 100% โดยไม่ต่อเน็ต/ไม่แตะดิสก์

evidence record (unified):
  {evidence_id, assessment_id, finding_ids[], asset_ids[], source_module, evidence_type,
   title, description, collected_at, content_hash, hash_algorithm, storage_reference,
   size_bytes, integrity_status, verification_status, confidence, redaction_applied,
   redaction_notes, metadata, created_at, custody[]}

finding_ids/asset_ids เป็น list เพราะ evidence หนึ่งอาจรองรับหลาย finding/asset เมื่อสมเหตุผล
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# ชนิด/สถานะ (ค่าที่อนุญาต)
# ---------------------------------------------------------------------------

# evidence_type ครอบคลุมหมวดตามสเปค (A–E) + รูปแบบไฟล์
EVIDENCE_TYPES = {
    # A. Reconnaissance
    "dns_observation", "whois_rdap", "subdomain", "certificate", "http_response_meta",
    "technology_fingerprint", "infrastructure", "service_metadata",
    # B. Vulnerability
    "vulnerability_result", "http_request", "http_response", "detection_method",
    "reproduction",
    # C. API
    "api_endpoint", "api_auth_result", "access_control_result", "api_response",
    "api_spec_observation",
    # D. Infrastructure / correlation
    "asset_relationship", "shared_infrastructure", "certificate_relationship",
    "dns_relationship", "technology_association", "correlation_reference",
    # E. Operational
    "execution_log", "module_status", "authorization_decision", "approval_record",
    "assessment_timestamp", "error_record",
    # file / raw
    "json_record", "txt", "csv", "html", "xml", "log_file", "screenshot",
    "pdf_report", "raw_excerpt",
}

# verification_status — สถานะการพิสูจน์ (แยกจาก integrity)
VERIFICATION_STATES = {
    "observed", "suspected", "verified", "reproduced", "not_reproducible", "inconclusive",
}

# integrity_status — สถานะความคงสภาพของ artifact/record
INTEGRITY_STATES = {
    "verified", "unverified", "compromised", "missing_artifact", "no_artifact",
}

# chain-of-custody event types (ตามสเปค 7)
CUSTODY_EVENTS = {
    "evidence_created", "evidence_collected", "evidence_validated", "evidence_stored",
    "evidence_accessed", "evidence_exported", "evidence_integrity_verified",
    "evidence_marked_suspicious", "evidence_archived",
}

# file type allow-list (ดูข้อ 5/17) — นามสกุล -> ปลอดภัยให้เก็บ artifact
ALLOWED_ARTIFACT_EXTS = {
    ".json", ".txt", ".csv", ".html", ".htm", ".xml", ".log", ".png", ".jpg",
    ".jpeg", ".gif", ".pdf", ".har",
}

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-:/]{0,120}$")
_ASSESSMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,80}$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_evidence_id(seq: int) -> str:
    return f"EVD-{datetime.now(timezone.utc).year}-{seq:06d}"


def make_custody_id(seq: int) -> str:
    return f"COC-{seq:06d}"


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def valid_id(value: Optional[str]) -> bool:
    return bool(value) and isinstance(value, str) and bool(_ID_RE.match(value))


def validate_submission(sub: Dict[str, Any]) -> Tuple[bool, str]:
    """ตรวจโครงสร้าง evidence submission ก่อน ingest — คืน (ok, reason)

    ต้องมี: assessment_id (ระบุการประเมิน/เหตุการณ์เดี่ยว), source_module, evidence_type
    """
    if not isinstance(sub, dict):
        return False, "NOT_A_DICT"
    aid = sub.get("assessment_id")
    if not aid or not isinstance(aid, str) or not _ASSESSMENT_RE.match(aid):
        return False, "INVALID_ASSESSMENT_ID"
    if not sub.get("source_module") or not isinstance(sub["source_module"], str):
        return False, "MISSING_SOURCE_MODULE"
    et = sub.get("evidence_type")
    if et not in EVIDENCE_TYPES:
        return False, f"INVALID_EVIDENCE_TYPE:{et}"
    vs = sub.get("verification_status", "observed")
    if vs not in VERIFICATION_STATES:
        return False, f"INVALID_VERIFICATION_STATUS:{vs}"
    for key in ("finding_ids", "asset_ids"):
        vals = sub.get(key)
        if vals is not None:
            if not isinstance(vals, (list, tuple)):
                return False, f"{key.upper()}_NOT_LIST"
            for v in vals:
                if not valid_id(v):
                    return False, f"INVALID_REF_IN_{key.upper()}:{v}"
    conf = sub.get("confidence", 0.5)
    try:
        c = float(conf)
        if not 0.0 <= c <= 1.0:
            return False, "CONFIDENCE_OUT_OF_RANGE"
    except (TypeError, ValueError):
        return False, "CONFIDENCE_NOT_NUMERIC"
    return True, "OK"


def new_record(evidence_id: str, sub: Dict[str, Any], *, content_hash: Optional[str],
               hash_algorithm: str, size_bytes: Optional[int], storage_reference: Optional[str],
               integrity_status: str, redaction_applied: bool, redaction_notes: str,
               collected_at: Optional[str]) -> Dict[str, Any]:
    """สร้าง evidence record จาก submission ที่ตรวจแล้ว (ยังไม่มี custody — เติมที่ store)"""
    def _norm_ids(key):
        vals = sub.get(key) or []
        single = sub.get(key[:-1])    # finding_id / asset_id
        if single:
            vals = list(vals) + [single]
        out, seen = [], set()
        for v in vals:
            if valid_id(v) and v not in seen:
                seen.add(v)
                out.append(v)
        return out

    return {
        "evidence_id": evidence_id,
        "assessment_id": sub["assessment_id"],
        "finding_ids": _norm_ids("finding_ids"),
        "asset_ids": _norm_ids("asset_ids"),
        "source_module": sub["source_module"],
        "evidence_type": sub["evidence_type"],
        "title": (sub.get("title") or sub["evidence_type"])[:200],
        "description": (sub.get("description") or "")[:2000],
        "collected_at": collected_at,                 # เวลาเก็บจริง (อาจ None ถ้าไม่มี)
        "collected_at_inferred": bool(sub.get("collected_at_inferred", collected_at is None)),
        "content_hash": content_hash,
        "hash_algorithm": hash_algorithm,
        "size_bytes": size_bytes,
        "storage_reference": storage_reference,       # path/pointer — ไม่ซ้ำไฟล์ใหญ่โดยไม่จำเป็น
        "integrity_status": integrity_status if integrity_status in INTEGRITY_STATES else "unverified",
        "verification_status": sub.get("verification_status", "observed"),
        "confidence": round(float(sub.get("confidence", 0.5)), 2),
        "redaction_applied": bool(redaction_applied),
        "redaction_notes": redaction_notes or "",
        "metadata": sub.get("metadata", {}) if isinstance(sub.get("metadata"), dict) else {},
        "created_at": now_iso(),
        "custody": [],
    }
