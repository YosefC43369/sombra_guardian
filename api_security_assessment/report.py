# -*- coding: utf-8 -*-
"""api_security_assessment/report.py — เรนเดอร์รายงาน + ข้อความแจ้งเตือน API (pure)"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

_TZ7 = timezone(timedelta(hours=7))

_CAT = {
    "authentication": "API Authentication", "authorization": "Broken Authorization (BOLA/BFLA)",
    "input_validation": "Input Validation", "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting", "graphql": "GraphQL Security",
    "cors": "CORS Misconfiguration", "info_disclosure": "Information Disclosure",
    "misconfiguration": "Security Misconfiguration",
}


def _ts(iso: str = "") -> str:
    try:
        dt = datetime.fromisoformat(iso) if iso else datetime.now(timezone.utc)
    except (ValueError, TypeError):
        dt = datetime.now(timezone.utc)
    return dt.astimezone(_TZ7).strftime("%Y-%m-%d %H:%M UTC+7")


def finding_alert(f: Dict[str, Any], target: str) -> str:
    conf = int(round(float(f.get("confidence", 0)) * 100))
    return (
        "[API SECURITY ALERT]\n\n"
        f"Target: {target}\n\n"
        f"Category: {_CAT.get(f['category'], f['category'])}\n\n"
        f"Severity: {f['severity']}\n\n"
        f"Status: {f['state']}\n\n"
        f"Endpoint:\n{f.get('endpoint','/')}\n\n"
        f"HTTP Method:\n{f.get('method','GET')}\n\n"
        f"Detection:\n{f.get('detail','')}\n\n"
        f"Evidence:\n{f.get('evidence','') or '[none]'}\n\n"
        f"Test Case:\n{f.get('test_case_id','-')}\n\n"
        f"Recommendation:\n{f.get('recommendation','-')}\n\n"
        f"Timestamp:\n{_ts(f.get('timestamp',''))}"
    )


def summary_text(a: Dict[str, Any]) -> str:
    c = a.get("counts", {})
    return (
        "[API SECURITY ASSESSMENT COMPLETE]\n\n"
        f"Target: {a.get('target')}\n\n"
        f"Endpoints analyzed: {a.get('endpoints_analyzed',0)}\n"
        f"Security checks executed: {a.get('checks_executed',0)}\n\n"
        "Findings:\n"
        f"* Critical: {c.get('CRITICAL',0)}\n"
        f"* High: {c.get('HIGH',0)}\n"
        f"* Medium: {c.get('MEDIUM',0)}\n"
        f"* Low: {c.get('LOW',0)}\n"
        f"* Informational: {c.get('INFORMATIONAL',0)}\n\n"
        f"Confirmed: {c.get('CONFIRMED',0)} · Potential: {c.get('POTENTIAL',0)} · "
        f"Informational: {c.get('INFORMATIONAL',0)}\n"
        f"Status: {a.get('status')} · Requests: {a.get('requests_made',0)}"
    )


def render_json(a: Dict[str, Any]) -> str:
    return json.dumps(a, ensure_ascii=False, indent=2, default=str)


def render_markdown(a: Dict[str, Any]) -> str:
    c = a.get("counts", {})
    info = a.get("api_info", {}) or {}
    L = [f"# API Security Assessment #{a.get('id')} — {a.get('target')}",
         f"- program: {a.get('program_id')} · status: {a.get('status')}",
         f"- API: {info.get('title') or '-'} {info.get('version') or ''}",
         f"- endpoints analyzed: {a.get('endpoints_analyzed',0)} · "
         f"checks: {a.get('checks_executed',0)} · requests: {a.get('requests_made',0)}",
         f"- categories: {', '.join(a.get('categories', []))}",
         f"- collected: {_ts(a.get('finished_iso') or a.get('created_iso',''))}",
         "",
         "## Summary",
         f"Critical {c.get('CRITICAL',0)} · High {c.get('HIGH',0)} · Medium {c.get('MEDIUM',0)} · "
         f"Low {c.get('LOW',0)} · Info {c.get('INFORMATIONAL',0)}  |  "
         f"Confirmed {c.get('CONFIRMED',0)} · Potential {c.get('POTENTIAL',0)}",
         ""]
    if a.get("denied_reason"):
        L.append(f"> denied/stopped: {a['denied_reason']}")
    L.append("## Findings")
    if not a.get("findings"):
        L.append("_ไม่พบ finding (การตรวจแบบจำกัด — ไม่ได้แปลว่าปลอดภัย)_")
    for f in a.get("findings", []):
        L.append(f"\n### [{f['severity']}/{f['state']}] {_CAT.get(f['category'],f['category'])} — {f.get('rule')}")
        L.append(f"- `{f.get('method')} {f.get('endpoint')}` param: `{f.get('param')}` · "
                 f"confidence {int(round(f.get('confidence',0)*100))}% · test {f.get('test_case_id')}")
        L.append(f"- detection: {f.get('detail')}")
        if f.get("evidence"):
            L.append(f"- evidence: `{f.get('evidence')}`")
        L.append(f"- recommendation: {f.get('recommendation')}")
        if f.get("ai_explanation"):
            L.append(f"- AI: {f['ai_explanation']}")
    if a.get("errors"):
        L.append("\n## Collection errors")
        for e in a["errors"][:15]:
            L.append(f"- {e.get('path')}: {e.get('reason')}")
    L.append("\n## Limitations")
    L.append("- safe-validation (detection) — ไม่ bypass auth/forge token/brute/DoS/เข้าถึงข้อมูลบุคคลที่สาม")
    L.append("- authz ใช้เฉพาะ test account + synthetic id ที่ operator ให้ · PUT/PATCH/DELETE ปิดโดยดีฟอลต์")
    L.append("- evidence ถูก sanitize · ตรวจเฉพาะ endpoint ที่มีในสเปค/ที่ให้มา (ไม่ brute-force)")
    return "\n".join(L)


def render_txt(a: Dict[str, Any]) -> str:
    import re
    return re.sub(r"[#`*]", "", render_markdown(a))
