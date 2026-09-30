"""
group_soc/normalization/schema.py — the RawEvent intermediate.

Collectors extract a RawEvent from a bus payload; the Normalizer turns it into a
privacy-safe SecurityEvent. The RawEvent is the ONLY place raw identifiers/text
live, and only transiently in memory — it is never persisted. Keeping it a distinct
type makes the "raw in, redacted out" boundary explicit and testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..constants import EventType, ObjectType


@dataclass
class RawEvent:
    event_type: str = EventType.MESSAGE_CREATED.value
    chat_id: int = 0
    ts: Optional[int] = None
    source: str = "telegram"
    correlation_id: Optional[str] = None

    # raw identifiers (hashed by the normalizer, never stored raw)
    actor_id: Optional[int] = None
    target_id: Optional[int] = None
    actor_label: Optional[str] = None      # username/display an admin already sees
    target_label: Optional[str] = None

    object_type: str = ObjectType.NONE.value
    object_id: Optional[str] = None

    # raw content (reduced to a hash+len by the normalizer; never stored raw)
    text: Optional[str] = None

    # (entity_kind, raw_value) pairs discovered by the collector
    entities: List[Tuple[str, str]] = field(default_factory=list)

    # non-PII framing the collector already knows
    severity: Optional[str] = None
    confidence: Optional[float] = None
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
