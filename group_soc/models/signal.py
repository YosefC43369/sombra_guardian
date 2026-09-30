"""
group_soc/models/signal.py — a SecuritySignal.

A signal is what a correlator or detector produces: "these events, together, look
like X, and here is how risky/confident that read is." A signal is not an alert —
many signals are deduped/suppressed before any human sees anything. A signal
records which events contributed (by id) so a timeline can be reconstructed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..constants import AnalyticState, VALID_ANALYTIC_STATES, MAX_LABEL_LEN, MAX_REASON_LEN
from ..util import now, gen_id, new_correlation_id, json_dump, json_load, clean_str
from ..version import SCHEMA_VERSION
from .entity import EntityRef
from .severity import RiskDimensions


@dataclass(frozen=True)
class SecuritySignal:
    signal_id: str = field(default_factory=lambda: gen_id("sig"))
    signal_type: str = "correlation"      # e.g. temporal|sequence|threshold|anomaly|campaign
    producer: str = ""                    # "correlation:temporal", "detection:threshold:join_burst"
    chat_id: int = 0
    ts: int = field(default_factory=now)
    correlation_id: str = field(default_factory=new_correlation_id)

    title: str = ""
    summary: str = ""

    dimensions: RiskDimensions = field(default_factory=RiskDimensions)
    analytic_state: str = AnalyticState.CORRELATED.value

    event_ids: List[str] = field(default_factory=list)
    entities: List[EntityRef] = field(default_factory=list)

    dedup_key: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        st = str(self.analytic_state)
        if st not in VALID_ANALYTIC_STATES:
            st = AnalyticState.CORRELATED.value
        object.__setattr__(self, "analytic_state", st)
        object.__setattr__(self, "title", clean_str(self.title, MAX_LABEL_LEN) or "")
        object.__setattr__(self, "summary", clean_str(self.summary, MAX_REASON_LEN) or "")
        object.__setattr__(self, "chat_id", int(self.chat_id or 0))
        if not self.dedup_key:
            object.__setattr__(self, "dedup_key", f"{self.chat_id}:{self.producer}:{self.title}")

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["dimensions"] = self.dimensions.as_dict()
        d["entities"] = [e.as_dict() for e in self.entities]
        return d

    def to_row(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "producer": self.producer,
            "chat_id": self.chat_id,
            "ts": self.ts,
            "correlation_id": self.correlation_id,
            "title": self.title,
            "summary": self.summary,
            "dimensions": json_dump(self.dimensions.as_dict()),
            "analytic_state": self.analytic_state,
            "event_ids": json_dump(self.event_ids),
            "entities": json_dump([e.as_dict() for e in self.entities]),
            "dedup_key": self.dedup_key,
            "metadata": json_dump(self.metadata),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "SecuritySignal":
        row = dict(row)
        return cls(
            signal_id=row.get("signal_id") or gen_id("sig"),
            signal_type=row.get("signal_type", "correlation"),
            producer=row.get("producer", ""),
            chat_id=int(row.get("chat_id") or 0),
            ts=int(row.get("ts") or now()),
            correlation_id=row.get("correlation_id") or new_correlation_id(),
            title=row.get("title", ""),
            summary=row.get("summary", ""),
            dimensions=RiskDimensions.from_dict(json_load(row.get("dimensions"))),
            analytic_state=row.get("analytic_state", AnalyticState.CORRELATED.value),
            event_ids=list(json_load(row.get("event_ids")) or []),
            entities=[EntityRef.from_dict(e) for e in (json_load(row.get("entities")) or [])],
            dedup_key=row.get("dedup_key", ""),
            metadata=json_load(row.get("metadata")),
            schema_version=int(row.get("schema_version") or SCHEMA_VERSION),
        )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "producer": self.producer,
            "chat_id": self.chat_id,
            "ts": self.ts,
            "correlation_id": self.correlation_id,
            "title": self.title,
            "analytic_state": self.analytic_state,
            "dimensions": self.dimensions.as_dict(),
            "event_count": len(self.event_ids),
        }
