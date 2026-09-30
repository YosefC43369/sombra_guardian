"""
group_soc/alerts/escalation.py — decide when a repeating alert escalates.

A condition that keeps re-firing past a threshold is escalated automatically so it
rises above one-off noise. Escalation only applies to non-terminal, not-yet-escalated
alerts.
"""

from __future__ import annotations

from ..constants import AlertStatus, TERMINAL_ALERT_STATUSES


def should_escalate(hit_count: int, threshold: int, status: str) -> bool:
    if status in TERMINAL_ALERT_STATUSES or status == AlertStatus.ESCALATED.value:
        return False
    return int(hit_count) >= int(threshold)
