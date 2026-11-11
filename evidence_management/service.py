# -*- coding: utf-8 -*-
"""evidence_management/service.py — บริการระดับสูง: ingest ชุด, verify, map, timeline, AI

ประสาน ingest.py/store.py/integrity.py/timeline.py ให้โมดูลอื่นเรียกได้สะดวก + AI ออปชัน
(reuse gemini เดิม) + access control (reuse permission ของบอต)

ไม่สแกน ไม่ correlate ซ้ำ — รับ output ที่โมดูลเดิมเก็บมาแล้ว
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from . import schema, ingest, store, integrity, timeline, redact

logger = logging.getLogger("modbot.evidence.service")


# ---------------------------------------------------------------------------
# ingest ระดับสูง
# ---------------------------------------------------------------------------

def submit(submission: Dict[str, Any], *, content: Any = None,
           actor: str = "assessment_module", path: Optional[str] = None) -> Dict[str, Any]:
    """ingest evidence หนึ่งรายการผ่าน policy (redaction/verify_on_ingest/enabled)"""
    pol = store.get_policy(path)
    if not pol.get("enabled", True):
        return {"error": "EVIDENCE_DISABLED"}
    return ingest.ingest(submission, content=content, actor=actor,
                         redaction_enabled=pol.get("redaction_enabled", True),
                         verify_on_ingest=pol.get("verify_on_ingest", True), path=path)


def submit_many(submissions: List[Dict[str, Any]], *, actor: str = "assessment_module",
                path: Optional[str] = None) -> Dict[str, Any]:
    """ingest หลายรายการ — คืน {ingested:[ids], errors:[...]}"""
    ids, errors = [], []
    for sub in submissions or []:
        res = submit(sub, actor=actor, path=path)
        if res.get("error"):
            errors.append({"reason": res.get("reason", res["error"]),
                           "type": sub.get("evidence_type")})
        else:
            ids.append(res["evidence_id"])
    return {"ingested": ids, "errors": errors, "count": len(ids)}


def ingest_task(task: Dict[str, Any], *, module_outputs: Optional[Dict[str, Any]] = None,
                correlation: Optional[Dict[str, Any]] = None,
                actor: str = "red_team_orchestrator",
                path: Optional[str] = None) -> Dict[str, Any]:
    """รับ orchestrator task (+ native outputs/correlation ออปชัน) -> ingest evidence ครบชุด

    assessment_id = task_id · ไม่สแกนใหม่ · operational + finding + recon + correlation evidence
    """
    pol = store.get_policy(path)
    if not pol.get("enabled", True):
        return {"error": "EVIDENCE_DISABLED"}
    assessment_id = task.get("task_id") or "STANDALONE"
    subs: List[Dict[str, Any]] = []
    subs += ingest.operational_from_task(task, assessment_id)
    for f in task.get("findings", []) or []:
        subs += ingest.from_unified_finding(f, assessment_id)
    for name, out in (module_outputs or {}).items():
        if name == "passive_recon":
            subs += ingest.from_passive_report(out, assessment_id)
    if correlation:
        subs += ingest.from_correlation_result(correlation, assessment_id)
    return submit_many(subs, actor=actor, path=path)


# ---------------------------------------------------------------------------
# verification (ไม่แก้ evidence เดิม; อัปเดตเฉพาะ integrity_status + custody)
# ---------------------------------------------------------------------------

def verify(evidence_id: str, *, content: Any = None, base_dir: Optional[str] = None,
           actor: str = "verifier", path: Optional[str] = None) -> Dict[str, Any]:
    """ตรวจ evidence — recompute hash (ถ้ามี content), ตรวจ artifact, ตรวจ custody chain

    อัปเดต integrity_status ตามผลจริง (verified/compromised/missing_artifact) + custody event
    """
    rec = store.get_record(evidence_id, path)
    if rec is None:
        return {"error": "EVIDENCE_NOT_FOUND", "evidence_id": evidence_id}

    # content_hash ครอบ "เนื้อหาที่เก็บจริง" (หลัง redact ถ้า redact ตอน ingest) —
    # redaction เป็น deterministic จึง redact content ที่ส่งมาตรวจด้วยวิธีเดียวกันก่อนเทียบ
    pol0 = store.get_policy(path)
    if isinstance(content, str) and rec.get("redaction_applied") and pol0.get("redaction_enabled", True):
        content, _ = redact.redact_text(content, 100000)

    artifact_exists = None
    artifact_readable = None
    ref = rec.get("storage_reference")
    if ref and base_dir:
        pol = store.get_policy(path)
        max_bytes = int(pol.get("max_file_size_mb", 25)) * 1024 * 1024
        ok, resolved = ingest.validate_artifact_path(ref, base_dir, max_bytes)
        artifact_exists = ok or resolved == "FILE_TOO_LARGE"
        if ok:
            try:
                with open(resolved, "rb") as fh:
                    data = fh.read()
                artifact_readable = True
                if content is None:
                    content = data
            except OSError:
                artifact_readable = False

    result = integrity.verify_record(rec, content=content,
                                     artifact_exists=artifact_exists,
                                     artifact_readable=artifact_readable)

    # อัปเดต integrity_status ตามผลจริง (ไม่สมมติว่าผ่าน)
    if result["hash_match"] is False:
        store.mark_integrity(evidence_id, "compromised", actor,
                             "hash mismatch on verification", path)
    elif "ARTIFACT_MISSING" in result["issues"]:
        store.mark_integrity(evidence_id, "missing_artifact", actor,
                             "artifact not found", path)
    elif result["verification_result"] == "passed" and rec.get("content_hash"):
        store.add_custody_event(evidence_id, "evidence_integrity_verified", actor,
                                "integrity verified", {"result": "passed"}, path)
    return result


def verify_assessment(assessment_id: str, *, path: Optional[str] = None) -> Dict[str, Any]:
    """ตรวจ custody chain + metadata ของ evidence ทั้งชุดของการประเมิน (ไม่มี content)"""
    recs = store.by_assessment(assessment_id, path)
    results = [integrity.verify_record(r) for r in recs]
    failed = [r for r in results if r["verification_result"] != "passed"]
    return {"assessment_id": assessment_id, "total": len(recs),
            "passed": len(results) - len(failed), "failed": len(failed),
            "failures": failed[:50], "note": integrity.INTEGRITY_LIMITS_NOTE}


# ---------------------------------------------------------------------------
# finding <-> evidence mapping
# ---------------------------------------------------------------------------

def evidence_for_finding(finding_id: str, *, path: Optional[str] = None) -> Dict[str, Any]:
    """คืน evidence ที่รองรับ finding หนึ่ง — จัดกลุ่มตามบทบาท (primary/supporting/...)"""
    recs = store.by_finding(finding_id, path)
    roles = {"primary": [], "supporting": [], "verification": [], "contradictory": [],
             "historical": [], "remediation": []}
    for r in recs:
        role = (r.get("metadata") or {}).get("evidence_role")
        if role not in roles:
            # อนุมานบทบาทจากชนิด/สถานะ (ไม่ยกระดับ: evidence มี ≠ finding confirmed)
            vs = r.get("verification_status")
            if r.get("evidence_type") == "vulnerability_result":
                role = "primary"
            elif vs in ("verified", "reproduced"):
                role = "verification"
            elif vs == "not_reproducible":
                role = "contradictory"
            else:
                role = "supporting"
        roles[role].append(r["evidence_id"])
    return {"finding_id": finding_id, "evidence_count": len(recs), "roles": roles,
            "note": "evidence ที่มีอยู่ไม่ได้ยืนยัน finding อัตโนมัติ — ดู verification_status"}


def access(evidence_id: str, actor: str, *, export: bool = False,
           path: Optional[str] = None) -> Dict[str, Any]:
    """อ่าน evidence + บันทึก custody (accessed/exported) — ควรผ่าน access control ของ caller"""
    rec = store.get_record(evidence_id, path)
    if rec is None:
        return {"error": "EVIDENCE_NOT_FOUND"}
    pol = store.get_policy(path)
    if pol.get("audit_trail_enabled", True):
        store.add_custody_event(evidence_id, "evidence_exported" if export else "evidence_accessed",
                                actor, "exported" if export else "accessed", path=path)
    return store.get_record(evidence_id, path)


def get_timeline(assessment_id: str, *, task: Optional[Dict[str, Any]] = None,
                 correlation: Optional[Dict[str, Any]] = None,
                 path: Optional[str] = None) -> Dict[str, Any]:
    recs = store.by_assessment(assessment_id, path)
    return timeline.build_timeline(recs, task=task, correlation=correlation)


# ---------------------------------------------------------------------------
# AI (ออปชัน, reuse gemini, ทนล้มเหลว)
# ---------------------------------------------------------------------------

async def ai_explain_evidence(finding_id: str, *, path: Optional[str] = None) -> Optional[str]:
    """ให้ AI เดิมอธิบายว่า evidence รองรับ finding อย่างไร — None ถ้า AI ไม่พร้อม

    ส่งเฉพาะ reference + เนื้อหาที่ redact แล้ว · AI ห้ามกุ evidence/ยกระดับเป็น confirmed
    """
    try:
        import gemini
    except Exception:
        return None
    recs = store.by_finding(finding_id, path)
    if not recs:
        return None
    lines = []
    for r in recs[:15]:
        lines.append(f"- [{r['evidence_type']}/{r['verification_status']}] {r['title']}: "
                     f"{r.get('description','')[:160]} (hash {('มี' if r.get('content_hash') else 'ไม่มี')})")
    prompt = (
        "คุณคือผู้ช่วยวิเคราะห์หลักฐานของทีม Red Team ที่ได้รับอนุญาต อธิบาย (ไทย กระชับ) ว่า "
        "evidence ด้านล่างรองรับ finding อย่างไร, ชี้ข้อมูล verification ที่ยังขาด, และเทียบ "
        "evidence ที่สนับสนุนกับที่ขัดแย้ง\n"
        "ข้อบังคับ: อ้างเฉพาะ evidence ที่ให้ · ห้ามกุ evidence/timestamp/HTTP response · "
        "ห้ามอ้างว่า exploit สำเร็จถ้าไม่มีหลักฐาน · ห้ามยกระดับ observation ที่ยังไม่ยืนยันเป็น "
        "finding ที่ confirmed · ทุกข้อความต้องโยงกลับ evidence หรือระบุชัดว่าเป็น 'บทวิเคราะห์'\n\n"
        f"finding: {finding_id}\nevidence:\n" + "\n".join(lines))
    try:
        ok, text = await gemini.ask_gemini(prompt)
        return text[:1500] if ok else None
    except Exception:
        logger.warning("evidence ai_explain failed", exc_info=True)
        return None
