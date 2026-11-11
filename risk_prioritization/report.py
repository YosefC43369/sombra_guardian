# -*- coding: utf-8 -*-
"""risk_prioritization/report.py — รายงานลำดับความเสี่ยง + PAYLOAD EXECUTION DETAILS (pure)

ต่อยอดรูปแบบรายงานเดิม (TXT/JSON/markdown) — ไม่สร้าง report engine ใหม่ · หัวข้อ payload
execution ตามโครงสร้างในสเปค (executed/suggested แยกชัด)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

_PRI_EMO = {"CRITICAL": "🔴", "HIGH": "🟠", "NEEDS_VERIFICATION": "🔵", "MEDIUM": "🟡",
            "LOW": "🟢", "INFORMATIONAL": "ℹ️"}


def summary_line(result: Dict[str, Any]) -> str:
    if result.get("error"):
        return f"❌ {result['error']}"
    c = result.get("counts", {})
    return (f"⚖️ {result.get('target') or '(assessment)'}: "
            f"C{c.get('CRITICAL',0)}/H{c.get('HIGH',0)}/NV{c.get('NEEDS_VERIFICATION',0)}/"
            f"M{c.get('MEDIUM',0)}/L{c.get('LOW',0)} · total {result.get('total',0)}")


def concise_report(result: Dict[str, Any]) -> str:
    if result.get("error"):
        return f"❌ Risk Prioritization: {result['error']}"
    c = result.get("counts", {})
    L = [f"⚖️ *Risk Prioritization* — `{result.get('result_id','(preview)')}`",
         f"target: {result.get('target') or '(assessment)'} · model v{result.get('model_version')}",
         f"priority: 🔴{c.get('CRITICAL',0)} 🟠{c.get('HIGH',0)} 🔵NV{c.get('NEEDS_VERIFICATION',0)} "
         f"🟡{c.get('MEDIUM',0)} 🟢{c.get('LOW',0)} ℹ️{c.get('INFORMATIONAL',0)}",
         ""]
    L.append("*ลำดับความเสี่ยงสูงสุด:*")
    for a in result.get("assessments", [])[:6]:
        L.append(f"{_PRI_EMO.get(a['risk_priority'],'•')} [{a['risk_priority']}/{a['risk_score']}] "
                 f"{a['title']} — sev {a['technical_severity']}, verify {a['verification_status']}")
    h = result.get("history") or {}
    if h and not h.get("baseline"):
        L.append(f"\nเทียบประวัติ: ใหม่ {len(h.get('new_findings', []))} · "
                 f"escalated {len(h.get('escalated', []))} · "
                 f"ไม่พบรอบนี้ {len(h.get('resolved_or_absent', []))}")
    if result.get("ai_summary"):
        L.append(f"\n🧠 AI: {result['ai_summary'][:450]}")
    return "\n".join(L)


def render_markdown(result: Dict[str, Any]) -> str:
    if result.get("error"):
        return f"# Risk Prioritization\n\n❌ {result['error']}"
    c = result.get("counts", {})
    L = [f"# Risk Prioritization Report — {result.get('result_id','(preview)')}",
         f"- target: {result.get('target') or '(assessment)'} · model version: {result.get('model_version')}",
         f"- generated: {result.get('generated_iso')} · source task: {result.get('source_task_id')}",
         f"- weights: {result.get('policy',{}).get('weights')}",
         "",
         "## Priority summary",
         f"CRITICAL {c.get('CRITICAL',0)} · HIGH {c.get('HIGH',0)} · "
         f"NEEDS_VERIFICATION {c.get('NEEDS_VERIFICATION',0)} · MEDIUM {c.get('MEDIUM',0)} · "
         f"LOW {c.get('LOW',0)} · INFORMATIONAL {c.get('INFORMATIONAL',0)}",
         ""]
    if result.get("ai_summary"):
        L.append(f"## AI analysis\n{result['ai_summary']}\n")
    L.append("## Prioritized findings")
    for a in result.get("assessments", []):
        L.append(f"\n### {_PRI_EMO.get(a['risk_priority'],'•')} [{a['risk_priority']} · "
                 f"score {a['risk_score']}] {a['title']}")
        L.append(f"- finding: `{a['finding_id']}` · category: {a['category']} · "
                 f"source: {a['source_module']}")
        L.append(f"- technical severity (scanner, preserved): **{a['technical_severity']}** · "
                 f"exposure: {a['exposure']}")
        L.append(f"- exploitability: {a['exploitability']} · asset criticality: {a['asset_criticality']} · "
                 f"evidence confidence: {a['evidence_confidence']}")
        L.append(f"- verification: {a['verification_status']}"
                 + (f" · cvss: {a['cvss']['value']} (src {a['cvss']['source']})" if a.get("cvss") else ""))
        if a.get("evidence_ids"):
            L.append(f"- evidence: {', '.join(a['evidence_ids'][:8])}")
        L.append(f"- why: {' | '.join(a['score_explanation'])}")
        L.append(f"- recommended action: {a['recommended_action']}")
    L.append("\n## Notes")
    L.append(f"- {result.get('notes','')}")
    return "\n".join(L)


def render_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2, default=str)


def render_txt(result: Dict[str, Any]) -> str:
    import re
    return re.sub(r"[#`*]", "", render_markdown(result))


# ---------------------------------------------------------------------------
# PAYLOAD EXECUTION DETAILS (ตามสเปค additional requirement §5)
# ---------------------------------------------------------------------------

def payload_execution_txt(transparency: Dict[str, Any]) -> str:
    """หัวข้อ 'PAYLOAD EXECUTION DETAILS' สำหรับ TXT report (executed + suggested แยกชัด)"""
    L = ["", "=" * 60, "PAYLOAD EXECUTION DETAILS", "=" * 60,
         f"(executed {transparency['counts']['executed']} · "
         f"verified {transparency['counts']['verified']} · "
         f"suggested/NOT_EXECUTED {transparency['counts']['suggested']})", ""]
    for e in transparency.get("executed_payloads", []):
        L += [
            f"Vulnerability: {e.get('vulnerability_type')}",
            f"Severity: {e.get('severity')}",
            f"Target: {e.get('target_url')}",
            f"Parameter: {e.get('parameter')}  ·  Injection point: {e.get('injection_point')}",
            "",
            "Executed Payload:",
            f"  {e.get('payload_value') or '[inert marker]'}",
            f"Payload ID / Category: {e.get('payload_id')} / {e.get('payload_category')}",
            f"Encoding / Profile: {e.get('payload_encoding')} / {e.get('payload_profile')}",
            f"Execution Status: {e.get('execution_status')}",
            f"HTTP Status: {e.get('http_status_code')}",
            f"Expected Behavior: {e.get('expected_behavior') or '-'}",
            f"Observed (evidence): {e.get('response_evidence') or '[none]'}",
            f"Verification: {e.get('verification_result')}",
            f"Evidence: {', '.join(transparency.get('evidence_references', [])[:3]) or '-'}",
            f"Confidence: {int(round(float(e.get('confidence',0))*100))}%",
            "-" * 40,
        ]
    sug = transparency.get("suggested_payloads", [])
    if sug:
        L += ["", "Suggested Payloads (NOT EXECUTED):"]
        for s in sug[:20]:
            L.append(f"  [NOT_EXECUTED] {s['payload_id']} ({s['payload_category']}): "
                     f"{s.get('payload_value')} — {s.get('relevance_reason')}")
    L.append("")
    L.append(f"NOTE: {transparency.get('note','')}")
    return "\n".join(L)


def payload_execution_json(transparency: Dict[str, Any]) -> Dict[str, Any]:
    """โครงสร้าง payload_execution สำหรับ JSON report (ไม่ซ้ำข้อมูลข้ามหลายส่วน)"""
    return {
        "payload_execution": {
            "executed_payloads": transparency.get("executed_payloads", []),
            "suggested_payloads": transparency.get("suggested_payloads", []),
            "verification_results": transparency.get("verification_results", []),
            "evidence_references": transparency.get("evidence_references", []),
            "counts": transparency.get("counts", {}),
        }
    }
