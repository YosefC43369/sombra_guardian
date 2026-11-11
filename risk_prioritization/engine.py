# -*- coding: utf-8 -*-
"""risk_prioritization/engine.py — ประสานการให้คะแนนความเสี่ยง (deterministic + AI ออปชัน)

แยกชัดจาก "การรันทดสอบ" (vulnerability execution) — รับ finding ที่โมดูลเดิมผลิตแล้ว +
บริบทจาก attack_surface_correlation (asset context) + evidence_management (evidence
confidence) แล้วให้คะแนนด้วย model.py จัดลำดับ และอธิบาย

ไม่ยกระดับ severity ของ finding · คง severity เดิมของ scanner · ไม่ถือว่า missing = ปลอดภัย
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import model, store

logger = logging.getLogger("modbot.risk.engine")

_WEB_MODULES = {"web_vulnerability_assessment", "wva", "api_security_assessment", "api",
                "vuln_probe"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# บริบทต่อ finding (asset context + evidence confidence)
# ---------------------------------------------------------------------------

def _asset_context(finding: Dict[str, Any], all_findings: List[Dict[str, Any]],
                   correlation: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    asset = finding.get("affected_asset") or ""
    source = finding.get("detection_source") or ""
    # related findings บน asset เดียวกัน (ไม่นับตัวเอง)
    related_findings = sum(1 for f in all_findings
                           if f.get("affected_asset") == asset) - 1
    related_assets = 0
    exposure = "internet_facing" if source in _WEB_MODULES else "unknown"
    if correlation:
        # degree ของ asset ใน correlation graph (ถ้า value ตรง)
        host = asset.split("/")[0].split(":")[0]
        for c in correlation.get("correlations", []):
            ev = " ".join(str(x) for x in c.get("evidence", []))
            if host and host in ev:
                related_assets += 1
    return {"exposure": exposure, "related_findings": max(0, related_findings),
            "related_assets": related_assets}


def _evidence_context(finding_id: str, base_confidence: float,
                      path: Optional[str]) -> Dict[str, Any]:
    """ดึง evidence confidence จาก evidence_management (ถ้ามี) — fallback: finding.confidence"""
    try:
        import evidence_management as evd
    except Exception:
        return {"supporting_count": 0, "integrity_ok": True, "verified": False,
                "contradictory": False, "base_confidence": base_confidence,
                "evidence_available": False}
    try:
        recs = evd.store.by_finding(finding_id) if finding_id else []
    except Exception:
        recs = []
    if not recs:
        return {"supporting_count": 0, "integrity_ok": True, "verified": False,
                "contradictory": False, "base_confidence": base_confidence,
                "evidence_available": False}
    verified = any(r.get("verification_status") in ("verified", "reproduced") for r in recs)
    contradictory = any(r.get("verification_status") == "not_reproducible" for r in recs)
    integrity_ok = all(r.get("integrity_status") != "compromised" for r in recs)
    confs = [float(r.get("confidence", 0)) for r in recs] or [base_confidence]
    return {"supporting_count": len(recs), "integrity_ok": integrity_ok,
            "verified": verified, "contradictory": contradictory,
            "base_confidence": max(confs), "evidence_available": True,
            "evidence_ids": [r["evidence_id"] for r in recs]}


def assess_finding(finding: Dict[str, Any], *, all_findings: Optional[List] = None,
                   correlation: Optional[Dict[str, Any]] = None,
                   weights: Optional[Dict[str, float]] = None,
                   confidence_threshold: float = 0.70,
                   path: Optional[str] = None) -> Dict[str, Any]:
    """ให้คะแนนความเสี่ยงของ finding หนึ่ง — คืน risk assessment record"""
    all_findings = all_findings or [finding]
    severity = (finding.get("severity") or "INFORMATIONAL").upper()
    verification = (finding.get("verification_status") or finding.get("state")
                    or "observed")
    fid = finding.get("finding_id") or finding.get("test_case_id") or ""
    meta = finding.get("metadata") or finding.get("raw") or {}
    cvss = meta.get("cvss_score") or meta.get("cvss")

    actx = _asset_context(finding, all_findings, correlation)
    ectx = _evidence_context(fid, float(finding.get("confidence", 0.5)), path)

    theoretical = (str(verification).lower() in ("observed", "informational")
                   and not ectx["evidence_available"])

    factors = {
        "severity": model.severity_factor(severity, cvss),
        "exploitability": model.exploitability_factor(
            str(verification), accessible=meta.get("accessible"),
            auth_required=meta.get("auth_required"),
            reproducible=(True if ectx["verified"] else None),
            theoretical=theoretical),
        "asset_criticality": model.asset_criticality_factor(
            exposure=actx["exposure"], importance=meta.get("asset_importance"),
            related_assets=actx["related_assets"],
            related_findings=actx["related_findings"],
            is_api_sensitive=(finding.get("detection_source") == "api_security_assessment")),
        "evidence_confidence": model.evidence_confidence_factor(
            base_confidence=ectx["base_confidence"],
            supporting_count=ectx["supporting_count"], integrity_ok=ectx["integrity_ok"],
            verified=ectx["verified"], contradictory=ectx["contradictory"]),
    }

    scored = model.score_finding(factors, severity=severity, verification=str(verification),
                                 weights=weights, confidence_threshold=confidence_threshold)

    cvss_source = None
    if cvss is not None:
        cvss_source = {"value": cvss, "source": meta.get("cvss_source", "finding_metadata"),
                       "timestamp": meta.get("cvss_timestamp")}

    return {
        "finding_id": fid,
        "title": finding.get("title") or finding.get("rule") or finding.get("category"),
        "category": finding.get("category"),
        "source_module": finding.get("detection_source") or finding.get("source_module"),
        "affected_asset": finding.get("affected_asset") or meta.get("endpoint", ""),
        # คงค่า severity เดิมของ scanner แยกจาก risk
        "original_severity": severity,
        "technical_severity": severity,
        "cvss": cvss_source,
        "exploitability": _label(factors["exploitability"]),
        "asset_criticality": _label(factors["asset_criticality"]),
        "evidence_confidence": factors["evidence_confidence"],
        "exposure": actx["exposure"].upper(),
        "verification_status": str(verification).upper(),
        "evidence_ids": ectx.get("evidence_ids", []),
        "risk_priority": scored["risk_priority"],
        "risk_score": scored["risk_score"],
        "model_version": scored["model_version"],
        "score_explanation": scored["score_explanation"],
        "recommended_action": _recommend(scored["risk_priority"], scored["needs_verification"],
                                          finding.get("remediation") or meta.get("remediation")),
        "assessed_at": _now(),
    }


def _label(x: float) -> str:
    if x >= 0.8:
        return "HIGH"
    if x >= 0.55:
        return "MODERATE"
    if x >= 0.3:
        return "LOW"
    return "MINIMAL"


def _recommend(priority: str, needs_verification: bool, remediation: Optional[str]) -> str:
    if needs_verification:
        return ("ทดสอบยืนยันเพิ่มแบบปลอดภัยก่อนจัดลำดับแก้ไข — ยังเป็น observation ที่ยังไม่ยืนยัน"
                + (f" · remediation: {remediation}" if remediation else ""))
    pri = {"CRITICAL": "แก้ไขทันที (ลำดับสูงสุด)", "HIGH": "แก้ไขเร่งด่วน",
           "MEDIUM": "วางแผนแก้ไขในรอบถัดไป", "LOW": "แก้ไขเมื่อสะดวก",
           "INFORMATIONAL": "บันทึกไว้เพื่อการรับรู้"}.get(priority, "ทบทวน")
    return pri + (f" · {remediation}" if remediation else "")


# ---------------------------------------------------------------------------
# assess ชุด + จัดลำดับ
# ---------------------------------------------------------------------------

def prioritize(findings: List[Dict[str, Any]], *, target: str = "",
               correlation: Optional[Dict[str, Any]] = None,
               source_task_id: Optional[str] = None,
               policy: Optional[Dict[str, Any]] = None,
               path: Optional[str] = None) -> Dict[str, Any]:
    """ให้คะแนน+จัดลำดับ finding ทั้งชุด — deterministic (ไม่มี AI)"""
    pol = dict(store.DEFAULT_POLICY)
    if policy:
        pol.update(policy)
    weights = pol.get("weights")
    threshold = float(pol.get("confidence_threshold", 0.70))

    assessments = [assess_finding(f, all_findings=findings, correlation=correlation,
                                  weights=weights, confidence_threshold=threshold, path=path)
                   for f in (findings or [])]
    order = {"CRITICAL": 5, "HIGH": 4, "NEEDS_VERIFICATION": 3, "MEDIUM": 2, "LOW": 1,
             "INFORMATIONAL": 0}
    assessments.sort(key=lambda a: (order.get(a["risk_priority"], 0), a["risk_score"]),
                     reverse=True)

    counts: Dict[str, int] = {}
    for a in assessments:
        counts[a["risk_priority"]] = counts.get(a["risk_priority"], 0) + 1

    return {
        "target": target,
        "source_task_id": source_task_id,
        "model_version": model.MODEL_VERSION,
        "generated_iso": _now(),
        "policy": {"weights": weights or model.DEFAULT_WEIGHTS,
                   "confidence_threshold": threshold},
        "assessments": assessments,
        "counts": counts,
        "total": len(assessments),
        "notes": ("risk priority แยกจาก technical severity · severity เดิมของ scanner คงไว้ · "
                  "NEEDS_VERIFICATION = observation ที่ยังไม่ยืนยัน (ไม่ใช่การปัดตก)"),
    }


# ---------------------------------------------------------------------------
# AI (ออปชัน, reuse gemini, ทนล้มเหลว)
# ---------------------------------------------------------------------------

async def ai_explain(result: Dict[str, Any]) -> Optional[str]:
    try:
        import gemini
    except Exception:
        return None
    top = result.get("assessments", [])[:10]
    lines = [f"- [{a['risk_priority']}/{a['risk_score']}] {a['title']} @ {a['affected_asset']} "
             f"(sev {a['technical_severity']}, verify {a['verification_status']})" for a in top]
    prompt = (
        "คุณคือผู้ช่วยจัดลำดับความเสี่ยงของทีม Red Team ที่ได้รับอนุญาต อธิบาย (ไทย กระชับ) "
        "ว่าทำไม finding เหล่านี้ถูกจัดลำดับเช่นนี้ และควรเริ่มตรวจสอบ/แก้อะไรก่อน\n"
        "ข้อบังคับ: อ้างเฉพาะข้อมูลที่ให้ · ห้ามกุหลักฐาน/CVSS/exploit · ห้ามยกระดับ "
        "observation ที่ยังไม่ยืนยันเป็น confirmed · แยก technical severity ออกจาก risk priority · "
        "ชี้จุดที่ควรทดสอบยืนยันเพิ่ม (NEEDS_VERIFICATION)\n\n"
        f"เป้าหมาย: {result.get('target')}\nสรุป: {result.get('counts')}\n\n"
        "finding (เรียงตามลำดับความเสี่ยง):\n" + "\n".join(lines))
    try:
        ok, text = await gemini.ask_gemini(prompt)
        return text[:1500] if ok else None
    except Exception:
        logger.warning("risk ai_explain failed", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# public entry + orchestrator integration
# ---------------------------------------------------------------------------

async def run(findings: List[Dict[str, Any]], *, target: str = "",
              correlation: Optional[Dict[str, Any]] = None,
              source_task_id: Optional[str] = None, ai: Optional[bool] = None,
              persist: bool = True, path: Optional[str] = None) -> Dict[str, Any]:
    pol = store.get_policy(path)
    if not pol.get("enabled", True):
        return {"error": "RISK_ENGINE_DISABLED"}
    previous = store.latest_for_target(target, path) if target else None
    result = prioritize(findings, target=target, correlation=correlation,
                        source_task_id=source_task_id, policy=pol, path=path)
    result["history"] = _compare(previous, result)

    use_ai = pol.get("use_ai", False) if ai is None else bool(ai)
    if use_ai and result.get("assessments"):
        result["ai_summary"] = await ai_explain(result)
    else:
        result["ai_summary"] = None

    if persist:
        result = store.save_result(result, path)
    return result


def _compare(previous: Optional[Dict[str, Any]], current: Dict[str, Any]) -> Dict[str, Any]:
    if not previous:
        return {"baseline": True, "note": "ไม่มีผลก่อนหน้า — baseline แรก"}
    prev = {a["finding_id"]: a for a in previous.get("assessments", [])}
    cur = {a["finding_id"]: a for a in current.get("assessments", [])}
    new = sorted(set(cur) - set(prev))
    resolved = sorted(set(prev) - set(cur))
    escalated, deescalated = [], []
    order = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "NEEDS_VERIFICATION": 2, "HIGH": 3,
             "CRITICAL": 4}
    for fid in set(prev) & set(cur):
        pp = order.get(prev[fid]["risk_priority"], 0)
        cp = order.get(cur[fid]["risk_priority"], 0)
        if cp > pp:
            escalated.append(fid)
        elif cp < pp:
            deescalated.append(fid)
    return {"baseline": False, "new_findings": new, "resolved_or_absent": resolved,
            "escalated": escalated, "deescalated": deescalated,
            "note": "'resolved_or_absent' = ไม่พบรอบนี้ ไม่ได้ยืนยันว่าถูกแก้"}


async def analyze_task(task_id: str, *, ai: Optional[bool] = None,
                       path: Optional[str] = None,
                       rt_path: Optional[str] = None) -> Dict[str, Any]:
    """โหลด task ที่ orchestrator เก็บไว้ -> จัดลำดับความเสี่ยง (ไม่รันทดสอบใหม่)"""
    try:
        from red_team_orchestrator import store as rt_store
    except Exception:
        return {"error": "ORCHESTRATOR_UNAVAILABLE"}
    task = rt_store.get_task(task_id, rt_path)
    if task is None:
        return {"error": "TASK_NOT_FOUND", "task_id": task_id}
    correlation = None
    corr_ref = task.get("correlation")
    if corr_ref and corr_ref.get("result_id"):
        try:
            import attack_surface_correlation as asc
            correlation = asc.store.get_result(corr_ref["result_id"])
        except Exception:
            correlation = None
    return await run(task.get("findings", []) or [], target=task.get("target", ""),
                     correlation=correlation, source_task_id=task_id, ai=ai,
                     persist=True, path=path)
