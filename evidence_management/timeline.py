# -*- coding: utf-8 -*-
"""evidence_management/timeline.py — สร้างไทม์ไลน์การประเมิน (pure)

ประกอบลำดับเหตุการณ์ของการประเมินจาก: orchestrator task (เริ่ม/auth/โมดูล/เสร็จ) +
evidence records (เก็บ/verify) + custody events + correlation ref

แยก "เวลาจริง" (actual) ออกจาก "เวลาอนุมาน" (inferred จากข้อมูลไม่ครบ) ตามสเปค 11
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _ev(ts, kind, source, detail, *, inferred=False, ref=None) -> Dict[str, Any]:
    return {"timestamp": ts, "timestamp_inferred": bool(inferred or ts is None),
            "kind": kind, "source": source, "detail": detail, "ref": ref}


def build_timeline(evidence: List[Dict[str, Any]], *,
                   task: Optional[Dict[str, Any]] = None,
                   correlation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """คืนไทม์ไลน์ {assessment_id, events:[...], has_inferred} เรียงตามเวลา

    evidence: list evidence record ของการประเมินเดียว
    task: orchestrator task record (ออปชัน)
    correlation: asc result (ออปชัน)
    """
    events: List[Dict[str, Any]] = []
    assessment_id = None

    if task:
        assessment_id = task.get("task_id")
        events.append(_ev(task.get("created_iso"), "assessment_started",
                          "red_team_orchestrator",
                          f"task {task.get('task_id')} ({task.get('task_type')})",
                          ref=task.get("task_id")))
        plan = task.get("plan") or {}
        events.append(_ev(task.get("started_iso"), "authorization_validated",
                          "red_team_orchestrator",
                          f"scope_authorized={plan.get('scope_authorized')}",
                          inferred=task.get("started_iso") is None))
        for m in task.get("module_results", []) or []:
            events.append(_ev(m.get("started_at"), "module_executed",
                              m.get("module"),
                              f"{m.get('module')}: {m.get('status')} "
                              f"({len(m.get('findings', []))} findings)",
                              inferred=m.get("started_at") is None))
        for f in task.get("findings", []) or []:
            events.append(_ev(None, "finding_discovered", f.get("detection_source", "module"),
                              f"{f.get('severity')}/{f.get('verification_status')} "
                              f"{f.get('title')}", inferred=True, ref=f.get("finding_id")))

    # evidence collection + custody
    for e in evidence or []:
        assessment_id = assessment_id or e.get("assessment_id")
        events.append(_ev(e.get("collected_at") or e.get("created_at"),
                          "evidence_collected", e.get("source_module"),
                          f"{e.get('evidence_type')}: {e.get('title')}",
                          inferred=e.get("collected_at") is None, ref=e.get("evidence_id")))
        for ce in e.get("custody", []):
            if ce.get("event_type") in ("evidence_integrity_verified",
                                        "evidence_marked_suspicious", "evidence_exported"):
                events.append(_ev(ce.get("timestamp"), ce["event_type"], ce.get("actor", "system"),
                                  ce.get("action", ""), ref=e.get("evidence_id")))

    if correlation:
        events.append(_ev(correlation.get("generated_iso"), "correlations_generated",
                          "attack_surface_correlation",
                          f"{correlation.get('counts', {}).get('total_relationships', 0)} relationships",
                          ref=correlation.get("result_id")))
        if correlation.get("ai_summary"):
            events.append(_ev(correlation.get("generated_iso"), "ai_analysis_completed",
                              "attack_surface_correlation", "AI summary produced", inferred=True))

    if task and task.get("finished_iso"):
        events.append(_ev(task.get("finished_iso"), "assessment_completed",
                          "red_team_orchestrator", f"status {task.get('status')}"))

    # เรียงตามเวลา (None/inferred ไปท้ายกลุ่มเวลาเดียวกันแต่คงลำดับเดิม)
    events.sort(key=lambda e: (e["timestamp"] or "9999", 0))
    return {"assessment_id": assessment_id, "events": events,
            "has_inferred": any(e["timestamp_inferred"] for e in events),
            "note": "เวลา inferred=True มาจากข้อมูลที่ไม่มี timestamp จริง — อย่าตีความเป็นเวลาเกิดจริง"}
