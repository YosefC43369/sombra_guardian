# -*- coding: utf-8 -*-
"""red_team_orchestrator/report.py — เรนเดอร์ plan/สถานะ/รายงานรวม (pure)"""

from __future__ import annotations

import json
from typing import Any, Dict

_EMO = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFORMATIONAL": "ℹ️"}


def plan_text(task: Dict[str, Any]) -> str:
    p = task.get("plan", {})
    L = [f"📋 *Execution Plan* — `{task['task_id']}`",
         f"type: {task['task_type']} · target: {task['target']}",
         f"status: {task['status']}",
         f"modules: {', '.join(p.get('selected_modules', [])) or '—'}",
         f"order: {' → '.join(p.get('execution_order', []))}",
         f"passive: {', '.join(p.get('passive_modules', [])) or '—'} · "
         f"active: {', '.join(p.get('active_modules', [])) or '—'}",
         f"authorization required: {p.get('authorization_required')} · "
         f"scope authorized: {p.get('scope_authorized')}",
         f"approval required: {p.get('approval_required')}"]
    if p.get("operational_risks"):
        L.append("risks: " + "; ".join(p["operational_risks"]))
    if task["status"] == "AWAITING_APPROVAL":
        L.append(f"\nอนุมัติเพื่อเริ่ม: `/rt_approve {task['task_id']}`")
    return "\n".join(L)


def summary_text(task: Dict[str, Any]) -> str:
    c = task.get("counts", {})
    L = [f"🧭 *Red Team Task* `{task['task_id']}` — {task['status']}",
         f"target: {task['target']} · type: {task['task_type']}"]
    if task.get("status_reason"):
        L.append(f"reason: {task['status_reason']}")
    mr = task.get("module_results", [])
    if mr:
        L.append("modules: " + " · ".join(
            f"{m['module']}={m['status']}({len(m['findings'])})" for m in mr))
    if c:
        L.append(f"findings: {c.get('total_findings',0)} — "
                 f"C{c.get('CRITICAL',0)}/H{c.get('HIGH',0)}/M{c.get('MEDIUM',0)}/"
                 f"L{c.get('LOW',0)}/I{c.get('INFORMATIONAL',0)} · "
                 f"confirmed {c.get('CONFIRMED',0)} / potential {c.get('POTENTIAL',0)}")
    if task.get("ai_summary"):
        L.append(f"\nAI: {task['ai_summary'][:400]}")
    return "\n".join(L)


def render_markdown(task: Dict[str, Any]) -> str:
    c = task.get("counts", {})
    L = [f"# Red Team Orchestration Report — {task['task_id']}",
         f"- target: {task['target']} · type: {task['task_type']} · status: {task['status']}",
         f"- created: {task.get('created_iso')} · finished: {task.get('finished_iso')}",
         ""]
    p = task.get("plan", {})
    L.append("## Execution")
    L.append(f"- modules: {' → '.join(p.get('execution_order', []))}")
    for m in task.get("module_results", []):
        L.append(f"- **{m['module']}**: {m['status']} · {len(m['findings'])} findings"
                 + (f" · errors: {m['errors']}" if m.get('errors') else ""))
    L.append("")
    L.append("## Summary")
    L.append(f"total {c.get('total_findings',0)} · C{c.get('CRITICAL',0)} H{c.get('HIGH',0)} "
             f"M{c.get('MEDIUM',0)} L{c.get('LOW',0)} I{c.get('INFORMATIONAL',0)} · "
             f"confirmed {c.get('CONFIRMED',0)} potential {c.get('POTENTIAL',0)}")
    if task.get("ai_summary"):
        L.append(f"\n### AI analysis\n{task['ai_summary']}")
    L.append("\n## Findings (unified)")
    if not task.get("findings"):
        L.append("_ไม่พบ finding (ไม่ได้แปลว่าปลอดภัย — การตรวจแบบจำกัด)_")
    for f in task.get("findings", []):
        L.append(f"\n### {_EMO.get(f['severity'],'•')} [{f['severity']}/{f['verification_status']}] "
                 f"{f['title']}")
        L.append(f"- source: {f['detection_source']} · category: {f['category']} · "
                 f"confidence {int(round(f.get('confidence',0)*100))}%")
        L.append(f"- asset: `{f['affected_asset']}`")
        if f.get("description"):
            L.append(f"- {f['description']}")
        if f.get("evidence_refs"):
            L.append(f"- evidence: `{'; '.join(f['evidence_refs'])}`")
        if f.get("remediation"):
            L.append(f"- remediation: {f['remediation']}")
    L.append("\n## Limitations")
    L.append("- ประสานโมดูลเดิม (safe-validation) — ไม่ exploit/ไม่ destructive · โมดูล active gate ด้วย scope")
    L.append("- evidence ถูก sanitize · AI ไม่กุผล (ถ้า AI ล้มเหลว รายงานยังออกได้)")
    return "\n".join(L)


def render_json(task: Dict[str, Any]) -> str:
    return json.dumps(task, ensure_ascii=False, indent=2, default=str)


def render_txt(task: Dict[str, Any]) -> str:
    import re
    return re.sub(r"[#`*]", "", render_markdown(task))
