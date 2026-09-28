"""
behavioral_intelligence.models.timeline — typed results for timeline, change
points, lifecycle and interaction structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List


class ChangeKind(str, Enum):
    USERNAME = "username_change"
    AVATAR = "avatar_change"
    BIO = "bio_change"
    FREQUENCY = "posting_frequency_change"
    LANGUAGE = "language_change"
    TOPIC = "topic_change"
    PLATFORM_MIGRATION = "platform_migration"
    URL = "url_change"
    DOMAIN = "domain_change"
    OTHER = "other"

    @classmethod
    def coerce(cls, raw: Any) -> "ChangeKind":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.OTHER


@dataclass
class TimelineEvent:
    at: float = 0.0
    kind: str = ""
    label: str = ""
    platform: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    evidence_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Timeline:
    entity_id: str = ""
    events: List[TimelineEvent] = field(default_factory=list)
    period_start: float = 0.0
    period_end: float = 0.0

    def sorted_events(self) -> List[TimelineEvent]:
        return sorted(self.events, key=lambda e: e.at)

    def to_dict(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id,
                "period_start": self.period_start,
                "period_end": self.period_end,
                "events": [e.to_dict() for e in self.sorted_events()]}


@dataclass
class ChangePoint:
    """A statistically detected change in an activity series (spec §7)."""
    at: float = 0.0
    kind: str = ChangeKind.FREQUENCY.value
    method: str = ""                   # cusum | zscore | ewma
    magnitude: float = 0.0             # standardised size of the change
    before_value: float = 0.0
    after_value: float = 0.0
    direction: str = "increase"        # increase | decrease
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("magnitude", "before_value", "after_value"):
            d[k] = round(d[k], 3)
        return d


@dataclass
class LifecycleStage:
    name: str = ""                     # first_observed | growth | peak | decline ...
    start: float = 0.0
    end: float = 0.0
    rate_per_day: float = 0.0
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["rate_per_day"] = round(self.rate_per_day, 3)
        return d


@dataclass
class Lifecycle:
    entity_id: str = ""
    first_observed: float = 0.0
    last_observed: float = 0.0
    peak_at: float = 0.0
    stages: List[LifecycleStage] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id,
                "first_observed": self.first_observed,
                "last_observed": self.last_observed,
                "peak_at": self.peak_at,
                "stages": [s.to_dict() for s in self.stages]}


@dataclass
class PlatformMigration:
    """Observed shift of activity from one platform to another (spec §24)."""
    from_platform: str = ""
    to_platform: str = ""
    from_last_activity: float = 0.0
    to_first_activity: float = 0.0
    overlap_days: float = 0.0
    shared_links: List[str] = field(default_factory=list)
    shared_username: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["overlap_days"] = round(self.overlap_days, 2)
        return d
