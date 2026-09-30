"""
cve_tracker.enrichment.timeline — build and render a CVE's dated lifecycle.

Collects the dated facts scattered across a record (published, last-modified,
KEV-added, KEV-due) plus change-detection events into a single ordered
timeline, de-duplicated by kind, so the Telegram detail view and the AI prompt
can show 'เผยแพร่ → advisory → KEV' cleanly.
"""

from __future__ import annotations

from typing import List

from ..models import CVERecord, TimelineEntry
from ..utils import thai_date

_KIND_LABEL = {
    "published": "เผยแพร่ CVE",
    "modified": "ปรับปรุงข้อมูลล่าสุด",
    "kev_added": "CISA เพิ่มเข้า KEV",
    "kev_due": "กำหนดเส้นตายแก้ไข (KEV due)",
    "advisory": "ออก advisory",
    "severity_changed": "ระดับความรุนแรงเปลี่ยน",
    "cvss_changed": "คะแนน CVSS เปลี่ยน",
    "reference_added": "เพิ่ม reference",
    "discovered": "ระบบตรวจพบครั้งแรก",
}


def rebuild(record: CVERecord) -> List[TimelineEntry]:
    """Recompute the timeline from the record's dated fields. Existing entries
    of other kinds (e.g. change events) are preserved; the derived ones are
    refreshed. Returns the sorted list and stores it on the record."""
    derived: List[TimelineEntry] = []
    if record.published_at:
        derived.append(TimelineEntry(at=record.published_at, kind="published",
                                     label=_KIND_LABEL["published"], source="derived"))
    if record.last_modified_at and record.last_modified_at != record.published_at:
        derived.append(TimelineEntry(at=record.last_modified_at, kind="modified",
                                     label=_KIND_LABEL["modified"], source="derived"))
    if record.in_kev and record.kev.date_added:
        derived.append(TimelineEntry(at=record.kev.date_added, kind="kev_added",
                                     label=_KIND_LABEL["kev_added"], source="cisa_kev"))
    if record.in_kev and record.kev.due_date:
        derived.append(TimelineEntry(at=record.kev.due_date, kind="kev_due",
                                     label=_KIND_LABEL["kev_due"], source="cisa_kev"))

    # Keep any pre-existing non-derived kinds (change events, discovered).
    preserved = [t for t in record.timeline
                 if t.kind not in ("published", "modified", "kev_added", "kev_due")]

    merged = _dedupe_by_kind(derived + preserved)
    merged.sort(key=lambda t: (t.at, t.kind))
    record.timeline = merged
    return merged


def add_event(record: CVERecord, at: int, kind: str, label: str = "", source: str = "system") -> None:
    """Append a one-off event (e.g. 'discovered', 'severity_changed') without a
    full rebuild. De-duplicates identical (kind, at)."""
    for t in record.timeline:
        if t.kind == kind and t.at == at:
            return
    record.timeline.append(TimelineEntry(
        at=at, kind=kind, label=label or _KIND_LABEL.get(kind, kind), source=source))
    record.timeline.sort(key=lambda t: (t.at, t.kind))


def _dedupe_by_kind(entries: List[TimelineEntry]) -> List[TimelineEntry]:
    seen = set()
    out: List[TimelineEntry] = []
    for t in entries:
        marker = (t.kind, t.at)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(t)
    return out


def render_thai(record: CVERecord, *, limit: int = 6) -> List[str]:
    """Render up to ``limit`` timeline lines like '18 ก.ย. 2569 — เผยแพร่ CVE'."""
    lines: List[str] = []
    for t in record.timeline[:limit]:
        label = t.label or _KIND_LABEL.get(t.kind, t.kind)
        lines.append(f"{thai_date(t.at, short=True)} — {label}")
    return lines
