"""
group_soc/commands/formatting.py — plain-text formatting for command output.

All command output is plain text (no markup), with any indicator already defanged by
the storage/normalization layers, so it is safe to send straight into a Telegram chat.
"""

from __future__ import annotations

import time
from typing import List

from ..models.alert import Alert
from ..models.case import Case
from ..models.incident import Incident


def hms(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(ts)))


def alert_line(a: Alert) -> str:
    return (f"[{a.priority_band}] {a.alert_id}  {a.title}  "
            f"({a.status}, sev={a.severity}, hits={a.hit_count})")


def alert_detail(a: Alert) -> str:
    return "\n".join([
        f"Alert {a.alert_id}",
        f"  title:    {a.title}",
        f"  summary:  {a.summary}",
        f"  priority: {a.priority_band} ({a.priority_score})",
        f"  severity: {a.severity}",
        f"  status:   {a.status}",
        f"  hits:     {a.hit_count}",
        f"  created:  {hms(a.created_at)}",
        f"  updated:  {hms(a.updated_at)}",
        f"  corr:     {a.correlation_id}",
    ])


def case_line(c: Case) -> str:
    return f"{c.case_id}  {c.title}  ({c.status}, sev={c.severity})"


def incident_line(i: Incident) -> str:
    return f"{i.incident_id}  [{i.severity}] {i.title}  ({i.classification}, {i.status})"


def bullet_list(header: str, lines: List[str], empty: str = "(none)") -> str:
    if not lines:
        return f"{header}\n{empty}"
    return header + "\n" + "\n".join(f"• {ln}" for ln in lines)
