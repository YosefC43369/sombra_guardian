"""group_soc/commands/timeline.py — /soc timeline handler."""

from __future__ import annotations

from typing import List, Optional

from ..timeline import render_timeline


def handle(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    if not args:
        return "ใช้งาน: /soc timeline <correlation_id | incident_id>"
    ident = args[0]
    inc = rt.incidents.get(ident)
    if inc is not None:
        entries = rt.timeline.build_for_incident(inc)
        return render_timeline(entries, header=f"TIMELINE {inc.incident_id}")
    entries = rt.timeline.build_for_correlation(ident)
    return render_timeline(entries, header=f"TIMELINE corr={ident}")
