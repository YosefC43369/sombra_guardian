"""
threat_actor_intelligence.timeline.report_timeline — reporting timeline.

A publication timeline across a set of reports: when each public source wrote
about an entity. This is the "reporting cadence" view — a burst of independent
reports in a short window is itself a signal (corroboration), and gaps show where
public visibility lapsed.
"""

from __future__ import annotations

from typing import Dict, List, Sequence

from ..models.report import Report
from .base import Timeline, TimelineEvent


class ReportTimelineBuilder:
    def build(self, reports: Sequence[Report], *, subject_type: str = "topic",
              subject_id: str = "") -> Timeline:
        tl = Timeline(subject_type=subject_type, subject_id=subject_id)
        for r in reports:
            at = r.published_at or r.collected_at
            if not at:
                continue
            tl.add(TimelineEvent(
                at=at, kind="report_published",
                label=f"{r.source or r.vendor}: {r.title}"[:120],
                detail={"report_id": r.report_id, "url": r.url,
                        "source": r.source, "vendor": r.vendor},
                sources=[r.source or r.vendor or "unknown"]))
        return tl

    def cadence(self, reports: Sequence[Report]) -> Dict[str, int]:
        return self.build(reports).bucket_by_month()


__all__ = ["ReportTimelineBuilder"]
