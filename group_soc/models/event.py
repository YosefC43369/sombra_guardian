"""
group_soc/models/event.py — the normalized SecurityEvent.

This is the SOC's atomic, immutable record. Everything downstream (correlation,
detection, timelines, stories) reads SecurityEvents, never raw Telegram objects.

Logical immutability: once created a SecurityEvent is never mutated; a change of
understanding produces a new Signal/Alert, not an edit. The dataclass is frozen to
enforce that in code.

Privacy: `actor_hash`/`target_hash` are salted hashes (see util.hash_id); free
text is reduced to `content_hash` + `content_len`. Raw ids/text never live here.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..constants import (
    EventType, VALID_EVENT_TYPES, ObjectType, Severity, VALID_SEVERITIES,
    AnalyticState, VALID_ANALYTIC_STATES,
)
from ..util import now, gen_id, new_correlation_id, json_dump, json_load
from ..version import SCHEMA_VERSION
from .entity import EntityRef
from .severity import clamp01


@dataclass(frozen=True)
class SecurityEvent:
    # identity / provenance
    event_id: str = field(default_factory=lambda: gen_id("evt"))
    event_type: str = EventType.MESSAGE_CREATED.value
    ts: int = field(default_factory=now)
    chat_id: int = 0
    source: str = "telegram"                 # provenance: telegram|blueteam|detection|intel|soc
    correlation_id: str = field(default_factory=new_correlation_id)

    # actors / objects (privacy-safe)
    actor_hash: Optional[str] = None
    target_hash: Optional[str] = None
    object_type: str = ObjectType.NONE.value
    object_id: Optional[str] = None          # e.g. message id (not PII on its own)

    # content (reduced)
    content_hash: Optional[str] = None
    content_len: int = 0

    # graph joins
    entities: List[EntityRef] = field(default_factory=list)

    # analytic framing
    severity: str = Severity.INFO.value
    confidence: float = 0.0
    analytic_state: str = AnalyticState.OBSERVED.value

    # free-form (must stay non-PII by construction — see normalizer)
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        et = str(self.event_type)
        if et not in VALID_EVENT_TYPES:
            et = EventType.MESSAGE_CREATED.value
        object.__setattr__(self, "event_type", et)

        sev = str(self.severity)
        if sev not in VALID_SEVERITIES:
            sev = Severity.INFO.value
        object.__setattr__(self, "severity", sev)

        st = str(self.analytic_state)
        if st not in VALID_ANALYTIC_STATES:
            st = AnalyticState.OBSERVED.value
        object.__setattr__(self, "analytic_state", st)

        object.__setattr__(self, "confidence", clamp01(self.confidence))
        object.__setattr__(self, "chat_id", int(self.chat_id or 0))
        object.__setattr__(self, "content_len", int(self.content_len or 0))

    # ---- serialization ----
    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["entities"] = [e.as_dict() for e in self.entities]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        data = dict(data or {})
        ents = [EntityRef.from_dict(e) for e in (data.get("entities") or [])]
        data["entities"] = ents
        # drop unknown keys defensively
        known = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_row(self) -> Dict[str, Any]:
        """Flat dict for the soc_events table."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "ts": self.ts,
            "chat_id": self.chat_id,
            "source": self.source,
            "correlation_id": self.correlation_id,
            "actor_hash": self.actor_hash,
            "target_hash": self.target_hash,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "content_hash": self.content_hash,
            "content_len": self.content_len,
            "severity": self.severity,
            "confidence": self.confidence,
            "analytic_state": self.analytic_state,
            "entities": json_dump([e.as_dict() for e in self.entities]),
            "context": json_dump(self.context),
            "metadata": json_dump(self.metadata),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "SecurityEvent":
        row = dict(row)
        ents = [EntityRef.from_dict(e) for e in (json_load(row.get("entities")) or [])]
        return cls(
            event_id=row.get("event_id") or gen_id("evt"),
            event_type=row.get("event_type", EventType.MESSAGE_CREATED.value),
            ts=int(row.get("ts") or now()),
            chat_id=int(row.get("chat_id") or 0),
            source=row.get("source", "telegram"),
            correlation_id=row.get("correlation_id") or new_correlation_id(),
            actor_hash=row.get("actor_hash"),
            target_hash=row.get("target_hash"),
            object_type=row.get("object_type", ObjectType.NONE.value),
            object_id=row.get("object_id"),
            content_hash=row.get("content_hash"),
            content_len=int(row.get("content_len") or 0),
            severity=row.get("severity", Severity.INFO.value),
            confidence=float(row.get("confidence") or 0.0),
            analytic_state=row.get("analytic_state", AnalyticState.OBSERVED.value),
            entities=ents,
            context=json_load(row.get("context")),
            metadata=json_load(row.get("metadata")),
            schema_version=int(row.get("schema_version") or SCHEMA_VERSION),
        )

    def to_payload(self) -> Dict[str, Any]:
        """PII-safe payload for the soc.event.recorded bus event."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "chat_id": self.chat_id,
            "ts": self.ts,
            "source": self.source,
            "correlation_id": self.correlation_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "analytic_state": self.analytic_state,
            "actor": self.actor_hash,        # already a hash
            "object_type": self.object_type,
        }
