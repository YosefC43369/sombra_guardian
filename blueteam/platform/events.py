"""
blueteam/platform/events.py — versioned, frozen event contracts (A3).

Every cross-module event is a frozen dataclass with a ``schema_version``. Fields are
add-only: never remove or repurpose one (that would break compatibility with a
subscriber or a persisted payload). Each event exposes :meth:`to_payload` which
produces the flat dict the existing workflow ``EventBus`` transports (the engine
matches ``event.type`` against a plain string), so these contracts document and
type the payloads without changing the bus.

See ``docs/blueteam/events.md`` for the catalogue.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional

SCHEMA_VERSION = 1

# ---- canonical event type strings (matched by workflow triggers) ----
INTEL_FEED_SYNCED = "intel.feed_synced"
INTEL_FEED_FAILED = "intel.feed_failed"
INTEL_IOC_MATCHED = "intel.ioc_matched"
RULE_MATCHED = "rule.matched"
RULE_STATE_CHANGED = "rule.state_changed"
POSTURE_SNAPSHOT_CREATED = "posture.snapshot_created"
POSTURE_SCORE_DROPPED = "posture.score_dropped"
REPORT_GENERATED = "report.generated"


@dataclass(frozen=True)
class _BaseEvent:
    schema_version: int = field(default=SCHEMA_VERSION, kw_only=True)
    ts: float = field(default_factory=time.time, kw_only=True)

    #: subclasses set the event type string
    type: str = field(default="", kw_only=True)

    def to_payload(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("type", None)
        d["schema_version"] = self.schema_version
        return d


@dataclass(frozen=True)
class FeedSynced(_BaseEvent):
    feed: str = ""
    added: int = 0
    updated: int = 0
    quarantined: int = 0
    total: int = 0
    duration_ms: int = 0
    type: str = field(default=INTEL_FEED_SYNCED, kw_only=True)


@dataclass(frozen=True)
class FeedFailed(_BaseEvent):
    feed: str = ""
    reason: str = ""
    circuit_open: bool = False
    type: str = field(default=INTEL_FEED_FAILED, kw_only=True)


@dataclass(frozen=True)
class IocMatched(_BaseEvent):
    chat_id: Optional[int] = None
    user_id: Optional[int] = None
    ioc_type: str = ""
    value_defanged: str = ""          # ALWAYS defanged (never a live IOC in a payload)
    confidence: int = 0
    severity: str = "medium"
    feeds: str = ""                   # comma-joined source names
    attack: str = ""
    subject: str = ""                 # non-sensitive id (sha256 of canonical value)
    type: str = field(default=INTEL_IOC_MATCHED, kw_only=True)


@dataclass(frozen=True)
class RuleMatched(_BaseEvent):
    chat_id: Optional[int] = None
    user_id: Optional[int] = None
    rule_id: str = ""
    rule_title: str = ""
    level: str = "medium"
    attack: str = ""
    mode: str = "enabled"             # shadow|canary|enabled
    subject: str = ""
    type: str = field(default=RULE_MATCHED, kw_only=True)


@dataclass(frozen=True)
class RuleStateChanged(_BaseEvent):
    rule_id: str = ""
    old_state: str = ""
    new_state: str = ""
    actor: Optional[int] = None
    reason: str = ""
    type: str = field(default=RULE_STATE_CHANGED, kw_only=True)


@dataclass(frozen=True)
class PostureSnapshotCreated(_BaseEvent):
    tenant: str = ""
    chat_id: Optional[int] = None
    score: float = 0.0
    grade: str = "F"
    coverage: float = 0.0
    type: str = field(default=POSTURE_SNAPSHOT_CREATED, kw_only=True)


@dataclass(frozen=True)
class PostureScoreDropped(_BaseEvent):
    tenant: str = ""
    chat_id: Optional[int] = None
    old_score: float = 0.0
    new_score: float = 0.0
    delta: float = 0.0
    type: str = field(default=POSTURE_SCORE_DROPPED, kw_only=True)


@dataclass(frozen=True)
class ReportGenerated(_BaseEvent):
    tenant: str = ""
    report_id: str = ""
    profile: str = "internal"         # client|internal
    fmt: str = "html"
    sha256: str = ""
    type: str = field(default=REPORT_GENERATED, kw_only=True)


__all__ = [
    "SCHEMA_VERSION", "FeedSynced", "FeedFailed", "IocMatched", "RuleMatched",
    "RuleStateChanged", "PostureSnapshotCreated", "PostureScoreDropped",
    "ReportGenerated",
    "INTEL_FEED_SYNCED", "INTEL_FEED_FAILED", "INTEL_IOC_MATCHED", "RULE_MATCHED",
    "RULE_STATE_CHANGED", "POSTURE_SNAPSHOT_CREATED", "POSTURE_SCORE_DROPPED",
    "REPORT_GENERATED",
]
