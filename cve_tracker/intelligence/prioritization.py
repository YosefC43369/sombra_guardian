"""
cve_tracker.intelligence.prioritization — map the score to a priority band.

Turns the transparent :class:`ScoreBreakdown` into a :class:`Priority` band plus
the human 'why', writes both onto the record, and provides the notification
ordering (rule §57): a CVE newly added to KEV or that just became CRITICAL is
processed ahead of a routine new CVE, which is ahead of a minor metadata change.
"""

from __future__ import annotations

from typing import List

from ..enums import Priority, ChangeKind
from ..models import CVERecord, ChangeSet
from .scoring import compute_breakdown


def band_for_score(score: int) -> Priority:
    if score >= 80:
        return Priority.URGENT
    if score >= 60:
        return Priority.HIGH
    if score >= 40:
        return Priority.MEDIUM
    if score >= 20:
        return Priority.LOW
    return Priority.INFO


def prioritize(record: CVERecord) -> CVERecord:
    """Compute and store the internal priority band, score and reasons."""
    bd = compute_breakdown(record)
    record.priority_score = bd.total
    record.priority = band_for_score(bd.total).value
    record.priority_reasons = bd.reasons[:6]
    return record


def priority_label_thai(record: CVERecord) -> str:
    """The 'Internal Priority: HIGH' line body. Always paired with a note that
    it is an internal signal, not an official CVSS."""
    band = record.priority or Priority.INFO.value
    th = {
        Priority.URGENT.value: "เร่งด่วนมาก",
        Priority.HIGH.value: "สูง",
        Priority.MEDIUM.value: "ปานกลาง",
        Priority.LOW.value: "ต่ำ",
        Priority.INFO.value: "ข้อมูลทั่วไป",
    }.get(band, band)
    return f"{band} ({th}) — สัญญาณจัดลำดับภายใน ไม่ใช่คะแนน CVSS ทางการ"


# ---------------- notification ordering ----------------

def event_priority_rank(change_set: ChangeSet) -> int:
    """Higher = processed first. Used when many events are queued at once."""
    if change_set is None:
        return 50  # a plain new CVE
    if change_set.of_kind(ChangeKind.KEV_STATUS.value):
        return 100
    sev = change_set.of_kind(ChangeKind.SEVERITY.value)
    if sev and str(sev.after).upper() == "CRITICAL":
        return 90
    if change_set.of_kind(ChangeKind.EXPLOIT_STATUS.value):
        return 85
    if change_set.of_kind(ChangeKind.CVSS.value):
        return 70
    if change_set.has_significant:
        return 60
    return 30  # minor metadata change


def order_for_dispatch(records: List[CVERecord]) -> List[CVERecord]:
    """Sort records newest-and-highest-priority first for alerting."""
    return sorted(
        records,
        key=lambda r: (r.priority_score, r.published_at or r.first_seen_at or 0),
        reverse=True,
    )
