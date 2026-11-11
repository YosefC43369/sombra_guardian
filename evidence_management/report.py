# -*- coding: utf-8 -*-
"""evidence_management/report.py — รายงานหลักฐาน 2 ระดับ (pure)

A. Executive Evidence Summary — สรุปต่อ finding (severity/asset/evidence/verification/risk/remediation)
B. Technical Evidence Appendix — รายละเอียด evidence (id/source/เวลา/excerpt/hash/custody/redaction)

reuse รูปแบบเรนเดอร์เดียวกับโมดูลอื่น (markdown/json/txt) — ไม่สร้าง reporting engine ใหม่
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from . import integrity

_SEV_EMO = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFORMATIONAL": "ℹ️"}
_INT_EMO = {"verified": "✅", "unverified": "⬜", "compromised": "⛔",
            "missing_artifact": "⚠️", "no_artifact": "·"}


def summary_line(evidence: List[Dict[str, Any]], assessment_id: str = "") -> str:
    n = len(evidence)
    comp = sum(1 for e in evidence if e.get("integrity_status") == "compromised")
    types = len({e.get("evidence_type") for e in evidence})
    return (f"🗂 {assessment_id or '(assessment)'}: evidence {n} · types {types}"
            + (f" · ⛔ compromised {comp}" if comp else ""))


def _finding_index(findings: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    idx = {}
    for f in findings or []:
        fid = f.get("finding_id")
        if fid:
            idx[fid] = f
    return idx


def executive_summary(evidence: List[Dict[str, Any]], *, assessment_id: str = "",
                      findings: Optional[List[Dict[str, Any]]] = None) -> str:
    """A. Executive Evidence Summary — จัดกลุ่มตาม finding"""
    fidx = _finding_index(findings)
    # group evidence by finding
    by_finding: Dict[str, List[Dict[str, Any]]] = {}
    unlinked = []
    for e in evidence:
        fids = e.get("finding_ids") or []
        if not fids:
            unlinked.append(e)
        for fid in fids:
            by_finding.setdefault(fid, []).append(e)

    L = [f"# Executive Evidence Summary — {assessment_id or '(assessment)'}",
         f"- findings with evidence: {len(by_finding)} · total evidence: {len(evidence)}",
         ""]
    for fid, evs in by_finding.items():
        f = fidx.get(fid, {})
        sev = f.get("severity", "—")
        vstates = sorted({e.get("verification_status") for e in evs})
        L.append(f"## {_SEV_EMO.get(sev,'•')} {f.get('title', fid)}  [{sev}]")
        L.append(f"- finding: `{fid}` · affected asset: `{f.get('affected_asset','—')}`")
        L.append(f"- evidence: {len(evs)} รายการ · verification: {', '.join(vstates)}")
        if f.get("description"):
            L.append(f"- risk: {f['description'][:300]}")
        if f.get("remediation"):
            L.append(f"- remediation: {f['remediation'][:300]}")
        # ไม่สรุปว่า confirmed เพราะมี evidence — บอกสถานะตามจริง
        confirmed = any(e.get("verification_status") in ("verified", "reproduced") for e in evs)
        L.append(f"- status: {'มีหลักฐานยืนยัน' if confirmed else 'ยังเป็นการสังเกต/ต้องยืนยันเพิ่ม'}")
        L.append("")
    if unlinked:
        L.append(f"## หลักฐานทั่วไป (ไม่ผูก finding): {len(unlinked)} รายการ")
    return "\n".join(L)


def technical_appendix(evidence: List[Dict[str, Any]], *, assessment_id: str = "") -> str:
    """B. Technical Evidence Appendix — รายละเอียดครบต่อ evidence"""
    L = [f"# Technical Evidence Appendix — {assessment_id or '(assessment)'}",
         f"- total evidence: {len(evidence)} · hash: {integrity.HASH_ALGORITHM}",
         f"- _{integrity.INTEGRITY_LIMITS_NOTE}_", ""]
    for e in evidence:
        mark = _INT_EMO.get(e.get("integrity_status"), "·")
        L.append(f"## {mark} `{e['evidence_id']}` {e.get('evidence_type')} — {e.get('title')}")
        L.append(f"- source module: {e.get('source_module')} · "
                 f"verification: {e.get('verification_status')} · "
                 f"confidence: {e.get('confidence')}")
        L.append(f"- collected: {e.get('collected_at') or '(inferred/none)'} · "
                 f"created: {e.get('created_at')}")
        if e.get("finding_ids"):
            L.append(f"- related findings: {', '.join(e['finding_ids'])}")
        if e.get("asset_ids"):
            L.append(f"- related assets: {', '.join(e['asset_ids'][:8])}")
        if e.get("description"):
            L.append(f"- detail: {e['description'][:500]}")
        excerpt = (e.get("metadata") or {}).get("excerpt")
        if excerpt:
            L.append(f"- excerpt: `{excerpt.get('method','')} {excerpt.get('url','')}` "
                     f"status {(e.get('metadata') or {}).get('response_status','')} "
                     f"(body {'truncated' if excerpt.get('body_truncated') else 'full'})")
        L.append(f"- hash ({e.get('hash_algorithm')}): `{e.get('content_hash') or '(no artifact)'}`"
                 + (f" · size {e.get('size_bytes')}B" if e.get("size_bytes") else ""))
        L.append(f"- integrity: {e.get('integrity_status')}"
                 + (f" · history: {len(e.get('integrity_history', []))} change(s)"
                    if e.get("integrity_history") else ""))
        cust = e.get("custody", [])
        if cust:
            root = integrity.merkle_root_of(cust)
            L.append(f"- chain of custody: {len(cust)} events · "
                     f"last `{cust[-1]['event_id']}` {cust[-1]['event_type']} · "
                     f"merkle `{(root or '')[:16]}…`")
        if e.get("redaction_applied"):
            L.append(f"- 🔒 redaction: {e.get('redaction_notes')}")
        L.append("")
    return "\n".join(L)


def verification_report(results: List[Dict[str, Any]], *, assessment_id: str = "") -> str:
    """รายงานผลการตรวจสอบ (verification) ของ evidence หลายรายการ"""
    passed = sum(1 for r in results if r.get("verification_result") == "passed")
    L = [f"# Evidence Verification Report — {assessment_id or '(assessment)'}",
         f"- verified: {passed}/{len(results)} passed",
         f"- _{integrity.INTEGRITY_LIMITS_NOTE}_", ""]
    for r in results:
        mark = "✅" if r.get("verification_result") == "passed" else "⛔"
        L.append(f"- {mark} `{r.get('evidence_id')}` — {r.get('verification_result')} "
                 f"(hash_match={r.get('hash_match')}, custody_ok={r.get('custody_chain_ok')})")
        if r.get("issues"):
            L.append(f"  - issues: {', '.join(r['issues'])}")
    return "\n".join(L)


def render_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, default=str)


def render_txt(markdown: str) -> str:
    import re
    return re.sub(r"[#`*]", "", markdown)
