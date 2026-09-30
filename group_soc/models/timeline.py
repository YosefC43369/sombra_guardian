"""
group_soc/models/timeline.py — a single ordered entry in a reconstructed timeline.

Timeline entries are a *derived view* built from events/signals/alerts/incidents by
the timeline builder. They can be persisted (soc_timeline) for durable incident
records, or built on the fly for a command response.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

from ..constants import MAX_REASON_LEN
from ..util import now, gen_id, json_dump, json_load, clean_str


#: what kind of thing a timeline entry points at
TIMELINE_KINDS = ("event", "signal", "alert", "case", "incident", "note", "action")


@dataclass(frozen=True)
class TimelineEntry:
    entry_id: str = field(default_factory=lambda: gen_id("tl"))
    chat_id: int = 0
    ts: int = field(default_factory=now)
    kind: str = "event"                 # one of TIMELINE_KINDS
    ref_id: str = ""                    # id of the referenced object
    correlation_id: Optional[str] = None
    actor_hash: Optional[str] = None
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        kind = str(self.kind)
        if kind not in TIMELINE_KINDS:
            kind = "event"
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "summary", clean_str(self.summary, MAX_REASON_LEN) or "")
        object.__setattr__(self, "chat_id", int(self.chat_id or 0))

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_row(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id, "chat_id": self.chat_id, "ts": self.ts,
            "kind": self.kind, "ref_id": self.ref_id,
            "correlation_id": self.correlation_id, "actor_hash": self.actor_hash,
            "summary": self.summary, "metadata": json_dump(self.metadata),
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "TimelineEntry":
        row = dict(row)
        return cls(
            entry_id=row.get("entry_id") or gen_id("tl"),
            chat_id=int(row.get("chat_id") or 0), ts=int(row.get("ts") or now()),
            kind=row.get("kind", "event"), ref_id=row.get("ref_id", ""),
            correlation_id=row.get("correlation_id"), actor_hash=row.get("actor_hash"),
            summary=row.get("summary", ""), metadata=json_load(row.get("metadata")),
        )
