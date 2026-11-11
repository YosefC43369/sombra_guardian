# -*- coding: utf-8 -*-
"""evidence_management/ingest.py — ingestion มาตรฐาน + ตัวแปลง output ของโมดูลเดิม (pure)

ขั้นตอน ingest (ตามสเปค 5): validate โครงสร้าง -> validate อ้างอิง -> บันทึก source ->
redact -> hash -> เก็บ record -> คืน evidence_id

ความปลอดภัยไฟล์: ตรวจชนิด/ขนาด/path (กัน path traversal) ก่อนอ่าน — ไม่เชื่อ input ดิบ

ตัวแปลง (submission builders) แปลง output ที่โมดูลเดิมเก็บมาแล้ว -> evidence submission
โดยไม่สแกนใหม่/ไม่เรียกโมดูลสแกน
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from . import schema, redact, integrity, store


# ---------------------------------------------------------------------------
# file safety (ข้อ 5 / 17)
# ---------------------------------------------------------------------------

def validate_artifact_path(file_path: str, base_dir: str,
                           max_bytes: int) -> Tuple[bool, str]:
    """ตรวจว่า file_path ปลอดภัยที่จะอ่าน: อยู่ใต้ base_dir, นามสกุล allow-list, ขนาดไม่เกิน

    กัน path traversal ด้วย realpath + commonpath (ไม่เชื่อสตริงล้วน)
    """
    if not file_path or not isinstance(file_path, str):
        return False, "EMPTY_PATH"
    try:
        base_real = os.path.realpath(base_dir)
        target_real = os.path.realpath(os.path.join(base_dir, file_path)
                                       if not os.path.isabs(file_path) else file_path)
    except (OSError, ValueError):
        return False, "PATH_RESOLVE_ERROR"
    if os.path.commonpath([base_real, target_real]) != base_real:
        return False, "PATH_TRAVERSAL"
    ext = os.path.splitext(target_real)[1].lower()
    if ext not in schema.ALLOWED_ARTIFACT_EXTS:
        return False, f"DISALLOWED_FILE_TYPE:{ext or '(none)'}"
    if not os.path.isfile(target_real):
        return False, "ARTIFACT_NOT_FOUND"
    try:
        if os.path.getsize(target_real) > max_bytes:
            return False, "FILE_TOO_LARGE"
    except OSError:
        return False, "STAT_ERROR"
    return True, target_real


# ---------------------------------------------------------------------------
# core ingest
# ---------------------------------------------------------------------------

def ingest(submission: Dict[str, Any], *, content: Any = None,
           actor: str = "assessment_module", redaction_enabled: bool = True,
           verify_on_ingest: bool = True, path: Optional[str] = None
           ) -> Dict[str, Any]:
    """ingest evidence หนึ่งรายการ — คืน record หรือ {error, reason}

    content: เนื้อหา inline (str/bytes/dict) ที่จะ hash; None = evidence เชิง metadata
    """
    ok, reason = schema.validate_submission(submission)
    if not ok:
        return {"error": "INVALID_SUBMISSION", "reason": reason}

    sub = dict(submission)
    redaction_notes = ""
    redacted = False
    if redaction_enabled:
        desc, d_red = redact.redact_text(sub.get("description", ""), 2000)
        sub["description"] = desc
        title, t_red = redact.redact_text(sub.get("title", ""), 200)
        sub["title"] = title
        meta = sub.get("metadata") or {}
        meta, m_red = _redact_metadata(meta)
        sub["metadata"] = meta
        redacted = d_red or t_red or m_red
        if content is not None and isinstance(content, str):
            content, c_red = redact.redact_text(content, 100000)
            redacted = redacted or c_red
        redaction_notes = redact.redaction_note(redacted)

    content_hash, size_bytes = integrity.hash_content(content)
    integrity_status = "no_artifact" if content_hash is None else (
        "verified" if verify_on_ingest else "unverified")

    record = schema.new_record(
        "pending", sub, content_hash=content_hash,
        hash_algorithm=integrity.HASH_ALGORITHM, size_bytes=size_bytes,
        storage_reference=sub.get("storage_reference"),
        integrity_status=integrity_status, redaction_applied=redacted,
        redaction_notes=redaction_notes, collected_at=sub.get("collected_at"))

    return store.create_record(record, actor=actor, path=path)


def _redact_metadata(meta: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """redact ค่าสตริงใน metadata (ตื้น + ลึกหนึ่งชั้น) — คืน (meta, was_redacted)"""
    redacted = False
    out: Dict[str, Any] = {}
    for k, v in (meta or {}).items():
        if isinstance(v, str):
            nv, r = redact.redact_text(v, 1000)
            out[k] = nv
            redacted = redacted or r
        elif isinstance(v, dict):
            nv, r = _redact_metadata(v)
            out[k] = nv
            redacted = redacted or r
        elif isinstance(v, list):
            nl = []
            for item in v[:200]:
                if isinstance(item, str):
                    ni, r = redact.redact_text(item, 1000)
                    nl.append(ni)
                    redacted = redacted or r
                else:
                    nl.append(item)
            out[k] = nl
        else:
            out[k] = v
    return out, redacted


# ---------------------------------------------------------------------------
# submission builders (output ของโมดูลเดิม -> evidence submission)
# ทุกตัว pure: คืน list ของ submission dict (ยังไม่ ingest)
# ---------------------------------------------------------------------------

def from_unified_finding(finding: Dict[str, Any], assessment_id: str) -> List[Dict[str, Any]]:
    """unified finding (orchestrator) -> vulnerability evidence + request/response ถ้ามี"""
    f = finding if isinstance(finding, dict) else {}
    fid = f.get("finding_id") or ""
    asset = f.get("affected_asset") or ""
    base = {
        "assessment_id": assessment_id,
        "source_module": f.get("detection_source") or "orchestrator",
        "finding_ids": [fid] if fid else [],
        "asset_ids": [asset] if asset else [],
        "collected_at": None,
        "metadata": {"category": f.get("category"), "severity": f.get("severity"),
                     "detection_source": f.get("detection_source")},
    }
    subs = [dict(base, evidence_type="vulnerability_result",
                 title=f.get("title") or f.get("category") or "finding",
                 description=f.get("description", ""),
                 verification_status=_map_verification(f.get("verification_status")),
                 confidence=float(f.get("confidence", 0.5)),
                 metadata=dict(base["metadata"], remediation=f.get("remediation")))]
    for ref in (f.get("evidence_refs") or [])[:10]:
        subs.append(dict(base, evidence_type="raw_excerpt", title="evidence excerpt",
                         description=str(ref),
                         verification_status=_map_verification(f.get("verification_status")),
                         confidence=float(f.get("confidence", 0.5))))
    return subs


def from_wva_finding(finding: Dict[str, Any], assessment_id: str) -> List[Dict[str, Any]]:
    """wva/api finding (schema เต็ม) -> vulnerability + redacted request/response excerpt"""
    f = finding if isinstance(finding, dict) else {}
    endpoint = f.get("endpoint") or f.get("target") or ""
    source = "api_security_assessment" if f.get("method") else "web_vulnerability_assessment"
    base = {
        "assessment_id": assessment_id, "source_module": source,
        "asset_ids": [endpoint] if endpoint and schema.valid_id(endpoint) else [],
        "collected_at": f.get("timestamp"),
        "verification_status": _map_verification(f.get("state")),
        "confidence": float(f.get("confidence", 0.5)),
        "metadata": {"category": f.get("category"), "rule": f.get("rule"),
                     "severity": f.get("severity"), "endpoint": endpoint,
                     "method": f.get("method"), "param": f.get("param")},
    }
    subs = [dict(base, evidence_type="vulnerability_result",
                 title=f.get("rule") or f.get("category") or "finding",
                 description=f.get("detail", ""))]
    # request/response excerpt (redact + ไม่เก็บ body เต็ม)
    if f.get("request") or f.get("response_excerpt"):
        excerpt, _ = redact.redact_http_excerpt(
            f.get("method"), endpoint, None, f.get("response_excerpt"))
        subs.append(dict(base, evidence_type="http_response",
                         title="request/response excerpt",
                         description=str(f.get("request", ""))[:500],
                         metadata=dict(base["metadata"], excerpt=excerpt,
                                       response_status=f.get("response_status"))))
    return subs


def from_passive_report(report: Dict[str, Any], assessment_id: str) -> List[Dict[str, Any]]:
    """passive_recon report -> recon evidence (dns/subdomain/cert/http/tech/infra)"""
    report = report if isinstance(report, dict) else {}
    cats = report.get("categories") or {}
    tgt = (report.get("target") or {})
    asset = tgt.get("domain") or ""
    collected = report.get("collected_at")
    source = "passive_recon"
    subs: List[Dict[str, Any]] = []

    def _mk(etype, title, desc, meta=None):
        subs.append({"assessment_id": assessment_id, "source_module": source,
                     "evidence_type": etype, "title": title, "description": desc,
                     "asset_ids": [asset] if asset and schema.valid_id(asset) else [],
                     "collected_at": collected, "verification_status": "observed",
                     "confidence": 0.8, "metadata": meta or {}})

    for r in (cats.get("dns", {}) or {}).get("records", [])[:50]:
        _mk("dns_observation", f"DNS {r.get('type')}", f"{r.get('type')} {r.get('value')}",
            {"record_type": r.get("type"), "record_value": r.get("value")})
    for r in (cats.get("subdomains", {}) or {}).get("records", [])[:200]:
        _mk("subdomain", "subdomain", r.get("value", ""), {"source": r.get("source")})
    tls = (cats.get("tls", {}) or {}).get("data")
    if tls:
        _mk("certificate", "TLS certificate",
            f"issuer {tls.get('issuer_cn')} · CN {tls.get('subject_cn')}",
            {"san": tls.get("san", []), "issuer_cn": tls.get("issuer_cn"),
             "not_after": tls.get("not_after"), "expired": tls.get("expired")})
    http = (cats.get("http", {}) or {}).get("data")
    if http:
        _mk("http_response_meta", "HTTP response metadata",
            f"status {http.get('status')} server {http.get('server')}",
            {"status": http.get("status"), "server": http.get("server"),
             "security_headers_missing": http.get("security_headers_missing", [])})
    for r in (cats.get("technology", {}) or {}).get("records", [])[:50]:
        _mk("technology_fingerprint", f"tech {r.get('tech')}",
            f"{r.get('tech')} {r.get('version') or ''}".strip(),
            {"tech": r.get("tech"), "version": r.get("version"),
             "confirmed": r.get("confirmed")})
    for r in (cats.get("infrastructure", {}) or {}).get("records", [])[:50]:
        if r.get("type") == "ip":
            _mk("infrastructure", "infrastructure", f"{r.get('value')}",
                {"asn": r.get("asn"), "name": r.get("name")})
    return subs


def from_correlation_result(result: Dict[str, Any], assessment_id: str) -> List[Dict[str, Any]]:
    """asc correlation result -> correlation_reference evidence (อ้าง asc ไม่ทำ correlate ซ้ำ)"""
    result = result if isinstance(result, dict) else {}
    rid = result.get("result_id") or ""
    subs: List[Dict[str, Any]] = []
    for c in (result.get("correlations") or [])[:200]:
        hypothesis = c.get("hypothesis", False)
        subs.append({
            "assessment_id": assessment_id, "source_module": "attack_surface_correlation",
            "evidence_type": "correlation_reference",
            "title": f"{c.get('relationship')} ({c.get('ownership')})",
            "description": c.get("explanation", ""),
            "asset_ids": [x for x in (c.get("source"), c.get("target")) if schema.valid_id(x)],
            "collected_at": c.get("detected_iso"),
            "verification_status": "suspected" if hypothesis else "observed",
            "confidence": float(c.get("confidence", 0.5)),
            "metadata": {"correlation_id": c.get("correlation_id"), "result_id": rid,
                         "relationship": c.get("relationship"), "ownership": c.get("ownership"),
                         "hypothesis": hypothesis, "evidence": c.get("evidence", [])},
        })
    return subs


def operational_from_task(task: Dict[str, Any], assessment_id: str) -> List[Dict[str, Any]]:
    """orchestrator task -> operational evidence (module status, auth decision, errors)"""
    task = task if isinstance(task, dict) else {}
    source = "red_team_orchestrator"
    subs: List[Dict[str, Any]] = []
    plan = task.get("plan") or {}
    subs.append({"assessment_id": assessment_id, "source_module": source,
                 "evidence_type": "authorization_decision",
                 "title": "authorization decision",
                 "description": f"scope_authorized={plan.get('scope_authorized')} "
                                f"program_id={plan.get('program_id')}",
                 "collected_at": task.get("started_iso"), "verification_status": "observed",
                 "confidence": 1.0,
                 "metadata": {"authorization_required": plan.get("authorization_required"),
                              "active_modules": plan.get("active_modules", [])}})
    for m in task.get("module_results", []) or []:
        subs.append({"assessment_id": assessment_id, "source_module": source,
                     "evidence_type": "module_status",
                     "title": f"module {m.get('module')}: {m.get('status')}",
                     "description": "; ".join(str(e) for e in (m.get("errors") or [])[:3]),
                     "collected_at": m.get("completed_at"), "verification_status": "observed",
                     "confidence": 1.0,
                     "metadata": {"module": m.get("module"), "status": m.get("status"),
                                  "findings": len(m.get("findings", []))}})
    return subs


def _map_verification(state: Optional[str]) -> str:
    """map สถานะจากโมดูลเดิม -> verification_status ของ evidence (ไม่ยกระดับเกินจริง)"""
    s = (state or "").upper()
    mapping = {
        "CONFIRMED": "verified", "VERIFIED": "verified", "REPRODUCED": "reproduced",
        "POTENTIAL": "suspected", "SUSPECTED": "suspected",
        "INFORMATIONAL": "observed", "OBSERVED": "observed",
        "NOT_REPRODUCIBLE": "not_reproducible", "INCONCLUSIVE": "inconclusive",
    }
    return mapping.get(s, "observed")
