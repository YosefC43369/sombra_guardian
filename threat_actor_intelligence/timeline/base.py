"""
threat_actor_intelligence.timeline.base — timeline primitives.

A ``TimelineEvent`` is a timestamped, evidence-anchored point on an entity's
history; a ``Timeline`` is the ordered set with span/bucketing helpers. Every
event *requires a timestamp* (spec TIMELINE ENGINE) — events without one are
dropped, not guessed. Events carry the evidence ref that dates them so the
timeline is auditable.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DAY = 86400.0


def iso(ts: float) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


@dataclass
class TimelineEvent:
    at: float
    kind: str
    label: str = ""
    subject_type: str = ""
    subject_id: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)

    @property
    def event_id(self) -> str:
        return hashlib.sha256(
            f"{self.subject_type}:{self.subject_id}|{self.at}|{self.kind}|{self.label}"
            .encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> Dict[str, Any]:
        return {"event_id": self.event_id, "at": self.at, "iso": iso(self.at),
                "kind": self.kind, "label": self.label,
                "subject_type": self.subject_type, "subject_id": self.subject_id,
                "detail": self.detail, "sources": list(self.sources)}


@dataclass
class Timeline:
    subject_type: str = ""
    subject_id: str = ""
    events: List[TimelineEvent] = field(default_factory=list)

    def add(self, event: TimelineEvent) -> bool:
        if not event.at:
            return False
        event.subject_type = event.subject_type or self.subject_type
        event.subject_id = event.subject_id or self.subject_id
        seen = {e.event_id for e in self.events}
        if event.event_id in seen:
            return False
        self.events.append(event)
        return True

    def sorted_events(self) -> List[TimelineEvent]:
        return sorted(self.events, key=lambda e: e.at)

    def span(self) -> tuple:
        if not self.events:
            return (0.0, 0.0)
        ts = [e.at for e in self.events]
        return (min(ts), max(ts))

    def duration_days(self) -> float:
        lo, hi = self.span()
        return round((hi - lo) / DAY, 1) if lo and hi else 0.0

    def bucket_by_month(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for e in self.sorted_events():
            key = iso(e.at)[:7]
            if key:
                out[key] = out.get(key, 0) + 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        lo, hi = self.span()
        return {"subject_type": self.subject_type, "subject_id": self.subject_id,
                "period_start": lo, "period_end": hi,
                "period_start_iso": iso(lo), "period_end_iso": iso(hi),
                "duration_days": self.duration_days(),
                "event_count": len(self.events),
                "by_month": self.bucket_by_month(),
                "events": [e.to_dict() for e in self.sorted_events()]}


__all__ = ["TimelineEvent", "Timeline", "iso", "DAY"]
