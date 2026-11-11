# -*- coding: utf-8 -*-
"""risk_prioritization/transparency.py — Payload Execution Transparency (pure)

บันทึก "payload ที่ถูกส่งจริง" ต่อ finding, แยก executed / suggested / verified อย่างชัดเจน,
เชื่อม executed payload กับ evidence, และสร้างหัวข้อรายงาน (TXT/JSON)

reuse: finding เดิมมี test_case_id (payload id) + request (ค่าที่ส่งจริง, sanitize แล้ว) +
response_status + response_excerpt/evidence + state/verification · payload registry เดิม
(payload_engine) เป็นแหล่ง metadata · classify.sanitize สำหรับ redact

หลักสำคัญ (acceptance criteria):
  * ไม่รายงานว่า payload ถูกส่ง ถ้าแค่ถูก "สร้าง/แนะนำ/เลือก" แต่ไม่ได้ส่งจริง
  * suggested (จาก AI/registry) ติดป้าย NOT_EXECUTED เสมอ ไม่นับเป็นช่องโหว่
  * reflected payload อย่างเดียว ไม่ใช่ confirmed XSS · 200 ไม่ใช่ sensitive-file disclosure
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from web_vulnerability_assessment.classify import sanitize as _sanitize
except Exception:  # pragma: no cover
    def _sanitize(x, limit=300):
        return (str(x) if x else "")[:limit]

# สถานะการรัน (executed)
EXEC_STATUS = ("COMPLETED", "BLOCKED", "INCONCLUSIVE", "SKIPPED", "FAILED")
# ผลการยืนยัน
VERIFY_RESULT = ("VERIFIED", "POTENTIAL", "FALSE_POSITIVE", "INCONCLUSIVE", "NOT_EXECUTED",
                 "REQUIRES_REVIEW")

_VERIFY_MAP = {
    "CONFIRMED": "VERIFIED", "VERIFIED": "VERIFIED", "REPRODUCED": "VERIFIED",
    "POTENTIAL": "REQUIRES_REVIEW", "SUSPECTED": "REQUIRES_REVIEW",
    "INFORMATIONAL": "POTENTIAL", "OBSERVED": "POTENTIAL",
    "NOT_REPRODUCIBLE": "FALSE_POSITIVE", "INCONCLUSIVE": "INCONCLUSIVE",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_src(f: Dict[str, Any]) -> Dict[str, Any]:
    """คืน finding ที่มี field การรัน (wva/api schema) — unified finding เก็บไว้ใน raw"""
    if "request" in f or "test_case_id" in f:
        return f
    raw = f.get("raw")
    if isinstance(raw, dict) and ("request" in raw or "test_case_id" in raw):
        return raw
    return f


def _payload_meta(pid: str, payload_set) -> Dict[str, Any]:
    if payload_set and pid:
        p = payload_set.by_id.get(pid)
        if p:
            return p
    return {}


def executed_record(finding: Dict[str, Any], payload_set=None) -> Dict[str, Any]:
    """สร้าง executed-payload record จาก finding (ค่าที่ส่งจริง + response evidence)"""
    src = _finding_src(finding)
    pid = src.get("test_case_id") or finding.get("finding_id") or ""
    meta = _payload_meta(pid, payload_set)
    sent_value = src.get("request", "")
    verification = (finding.get("verification_status") or src.get("state") or "observed")
    return {
        "finding_id": finding.get("finding_id") or src.get("test_case_id") or pid,
        "vulnerability_type": finding.get("category") or src.get("category"),
        "severity": finding.get("severity") or src.get("severity"),
        "target_url": finding.get("affected_asset") or src.get("endpoint") or src.get("target", ""),
        "http_method": src.get("method", "GET"),
        "parameter": src.get("param", "-"),
        "injection_point": _injection_point(src),
        "payload_id": pid,
        "payload_name": meta.get("name") or meta.get("description") or pid,
        "payload_category": meta.get("category") or finding.get("category"),
        "payload_value": _sanitize(sent_value, 200),       # redact secret + ตัดยาว
        "payload_encoding": meta.get("encoding", "none"),
        "payload_profile": meta.get("profile", "SAFE_STANDARD"),
        "execution_timestamp": src.get("timestamp") or finding.get("timestamp"),
        "execution_status": _exec_status(src),
        "http_status_code": src.get("response_status"),
        "response_evidence": _sanitize(src.get("response_excerpt") or src.get("evidence", ""), 200),
        "verification_result": _VERIFY_MAP.get(str(verification).upper(), "REQUIRES_REVIEW"),
        "confidence": round(float(finding.get("confidence", src.get("confidence", 0.5))), 2),
        "source_module": finding.get("detection_source") or finding.get("source_module")
        or ("api_security_assessment" if src.get("method") else "web_vulnerability_assessment"),
        "expected_behavior": meta.get("expected", ""),
        "input_context": meta.get("context", ""),
        "selection_reason": f"context={meta.get('context') or '-'}, detection={meta.get('detection_method') or '-'}",
    }


def _injection_point(src: Dict[str, Any]) -> str:
    if src.get("method") and src["method"] not in ("GET", "HEAD"):
        return "body"
    if src.get("param") and src["param"] not in ("-", None):
        return "query_parameter"
    if (src.get("param") or "").lower() in ("origin", "host"):
        return "http_header"
    return "endpoint"


def _exec_status(src: Dict[str, Any]) -> str:
    status = src.get("response_status")
    if status in (0, None):
        return "INCONCLUSIVE"
    if status in (403, 406) and (src.get("state") not in ("CONFIRMED",)):
        return "BLOCKED"       # อาจโดน WAF/นโยบาย
    return "COMPLETED"


def executed_from_findings(findings: List[Dict[str, Any]], payload_set=None
                           ) -> List[Dict[str, Any]]:
    """เฉพาะ finding ที่ "ส่ง payload จริง" (มี request/test_case_id) -> executed records"""
    out = []
    for f in findings or []:
        src = _finding_src(f)
        if src.get("request") or src.get("test_case_id"):
            out.append(executed_record(f, payload_set))
    return out


def verified_payloads(executed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """executed ที่ผ่านเกณฑ์ยืนยัน (VERIFIED + มี response evidence) — ไม่เหมารวม"""
    out = []
    for e in executed:
        if e["verification_result"] == "VERIFIED" and e.get("response_evidence"):
            out.append({"finding_id": e["finding_id"], "payload_id": e["payload_id"],
                        "verification_method": "evidence-backed confirmation",
                        "evidence": e["response_evidence"],
                        "http_status_code": e["http_status_code"]})
    return out


def suggested_payloads(findings: List[Dict[str, Any]], payload_set, *,
                       profile: str = "SAFE_STANDARD", max_per_category: int = 5
                       ) -> List[Dict[str, Any]]:
    """payload เพิ่มเติมจาก registry ที่ 'เกี่ยวข้อง' แต่ยังไม่ได้ส่ง — ติดป้าย NOT_EXECUTED

    (ส่วนนี้คือ 'suggested' — registry-driven; AI อาจเสริมเหตุผลได้ แต่ยังคง NOT_EXECUTED)
    """
    if not payload_set:
        return []
    cats = {f.get("category") for f in (findings or []) if f.get("category")}
    executed_ids = set()
    for f in findings or []:
        src = _finding_src(f)
        if src.get("test_case_id"):
            executed_ids.add(src["test_case_id"])
    out = []
    for cat in sorted(c for c in cats if c):
        pool = payload_set.for_profile(cat, profile) if hasattr(payload_set, "for_profile") \
            else payload_set.by_category.get(cat, [])
        n = 0
        for p in pool:
            if p["id"] in executed_ids or n >= max_per_category:
                continue
            out.append({
                "payload_id": p["id"], "payload_name": p.get("name") or p.get("description"),
                "payload_category": cat, "payload_value": _sanitize(p.get("test_string", ""), 120),
                "payload_profile": p.get("profile", "SAFE_STANDARD"),
                "input_context": p.get("context", ""),
                "status": "NOT_EXECUTED",
                "relevance_reason": f"หมวด {cat} มี finding อยู่แล้ว — test case นี้ตรวจ "
                                    f"{p.get('subcategory') or p.get('rule','')} ({p.get('context') or 'generic'}) "
                                    f"ที่ยังไม่ได้ส่ง",
            })
            n += 1
    return out


def build_transparency(findings: List[Dict[str, Any]], *, payload_set=None,
                       profile: str = "SAFE_STANDARD",
                       include_suggested: bool = True) -> Dict[str, Any]:
    """โครงสร้าง payload_execution ครบ: executed / suggested / verified / evidence refs"""
    executed = executed_from_findings(findings, payload_set)
    verified = verified_payloads(executed)
    suggested = suggested_payloads(findings, payload_set, profile=profile) \
        if include_suggested else []
    evidence_refs = sorted({eid for f in (findings or [])
                            for eid in (f.get("evidence_ids") or [])})
    return {
        "executed_payloads": executed,
        "suggested_payloads": suggested,
        "verification_results": verified,
        "evidence_references": evidence_refs,
        "generated_iso": _now(),
        "counts": {"executed": len(executed), "suggested": len(suggested),
                   "verified": len(verified),
                   "requires_review": sum(1 for e in executed
                                          if e["verification_result"] == "REQUIRES_REVIEW")},
        "note": ("executed = ส่งจริง · suggested = NOT_EXECUTED (ไม่ใช่ช่องโหว่) · "
                 "verified = มีหลักฐานยืนยันตามเกณฑ์ · reflected/200 อย่างเดียวไม่ถือว่ายืนยัน"),
    }


def link_to_evidence(executed: List[Dict[str, Any]], assessment_id: str, *,
                     actor: str = "payload_transparency",
                     path: Optional[str] = None) -> Dict[str, Any]:
    """ส่ง executed-payload record เข้า evidence_management (ถ้ามี) — คืน {ingested, errors}"""
    try:
        import evidence_management as evd
    except Exception:
        return {"ingested": 0, "errors": 0, "reason": "EVIDENCE_UNAVAILABLE"}
    subs = []
    for e in executed:
        subs.append({
            "assessment_id": assessment_id,
            "source_module": e.get("source_module") or "payload_transparency",
            "evidence_type": "http_request",
            "title": f"executed payload {e['payload_id']}",
            "finding_ids": [e["finding_id"]] if e.get("finding_id") else [],
            "description": f"{e['http_method']} {e['target_url']} param={e['parameter']} "
                           f"payload={e['payload_value']}",
            "verification_status": _evd_verif(e["verification_result"]),
            "confidence": e.get("confidence", 0.5),
            "collected_at": e.get("execution_timestamp"),
            "metadata": {"payload_id": e["payload_id"], "payload_category": e["payload_category"],
                         "execution_status": e["execution_status"],
                         "http_status_code": e["http_status_code"],
                         "response_evidence": e["response_evidence"],
                         "payload_profile": e["payload_profile"]},
        })
    try:
        res = evd.service.submit_many(subs, actor=actor, path=path)
        return {"ingested": res.get("count", 0), "errors": len(res.get("errors", [])),
                "evidence_ids": res.get("ingested", [])}
    except Exception:
        return {"ingested": 0, "errors": len(subs), "reason": "INGEST_FAILED"}


def _evd_verif(v: str) -> str:
    return {"VERIFIED": "verified", "REQUIRES_REVIEW": "suspected",
            "FALSE_POSITIVE": "not_reproducible", "INCONCLUSIVE": "inconclusive",
            "POTENTIAL": "observed"}.get(v, "observed")
