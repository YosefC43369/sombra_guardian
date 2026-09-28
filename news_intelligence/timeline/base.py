"""
news_intelligence.timeline.base — evidence-dated timeline primitives.

A timeline is an ordered list of ``TimelineEntry`` objects, each anchored to the
article (and thus the public source) that dates it. Timelines never invent dates:
an entry's timestamp is the article's publication date, and the entry cites the
article. New-vs-historical is decided purely by the timestamp relative to a cutoff.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class TimelineEntry:
    ts: float
    label: str
    article_id: str = ""
    source: str = ""
    title: str = ""
    kind: str = "mention"
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def iso(self) -> str:
        try:
            return time.strftime("%Y-%m-%d", time.gmtime(self.ts)) if self.ts else ""
        except Exception:
            return ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["iso"] = self.iso
        return d


@dataclass
class Timeline:
    subject: str
    subject_type: str = ""
    entries: List[TimelineEntry] = field(default_factory=list)

    def add(self, entry: TimelineEntry) -> None:
        self.entries.append(entry)

    def sorted(self) -> List[TimelineEntry]:
        return sorted(self.entries, key=lambda e: e.ts)

    def first(self) -> float:
        ts = [e.ts for e in self.entries if e.ts]
        return min(ts) if ts else 0.0

    def last(self) -> float:
        return max((e.ts for e in self.entries), default=0.0)

    def new_since(self, cutoff: float) -> List[TimelineEntry]:
        return [e for e in self.sorted() if e.ts >= cutoff]

    def historical(self, cutoff: float) -> List[TimelineEntry]:
        return [e for e in self.sorted() if e.ts < cutoff]

    def to_dict(self) -> Dict[str, Any]:
        s = self.sorted()
        return {"subject": self.subject, "subject_type": self.subject_type,
                "first": self.first(), "last": self.last(), "count": len(s),
                "entries": [e.to_dict() for e in s]}


class BaseTimelineBuilder:
    subject_type = ""

    def __init__(self, store):
        self.store = store

    def _from_store_events(self, subject_key: str, subject_label: str) -> Timeline:
        tl = Timeline(subject=subject_label, subject_type=self.subject_type)
        for ev in self.store.timeline_for(subject_key):
            tl.add(TimelineEntry(
                ts=float(ev.get("ts", 0.0) or 0.0),
                label=ev.get("label", ""), article_id=ev.get("article_id", ""),
                source=ev.get("source", ""), title=ev.get("title", ""),
                kind=ev.get("subject_type", self.subject_type),
                detail={k: v for k, v in ev.items()
                        if k not in ("ts", "label", "article_id", "source",
                                     "title", "subject_type", "event_id")}))
        return tl


__all__ = ["TimelineEntry", "Timeline", "BaseTimelineBuilder"]
