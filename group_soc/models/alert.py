"""
group_soc/models/alert.py — an Alert.

An alert is a prioritized signal that survived dedup/suppression and is worth an
analyst's attention. It carries a lifecycle status and the running counters that
drive escalation (how many times its dedup_key has fired).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..constants import (
    AlertStatus, VALID_ALERT_STATUSES, ALERT_TRANSITIONS,
    Severity, VALID_SEVERITIES, MAX_LABEL_LEN, MAX_REASON_LEN,
)
from ..util import now, gen_id, new_correlation_id, json_dump, json_load, clean_str
from ..version import SCHEMA_VERSION
from .severity import PriorityScore, DEFAULT_WEIGHTS


@dataclass(frozen=True)
class Alert:
    alert_id: str = field(default_factory=lambda: gen_id("alt"))
    chat_id: int = 0
    correlation_id: str = field(default_factory=new_correlation_id)
    signal_id: str = ""
    dedup_key: str = ""

    title: str = ""
    summary: str = ""
    severity: str = Severity.MEDIUM.value
    priority_band: str = "P3"
    priority_score: float = 0.0

    status: str = AlertStatus.NEW.value
    assignee_hash: Optional[str] = None

    # counters that drive escalation / grouping
    hit_count: int = 1                    # number of signals folded into this alert
    group_id: Optional[str] = None        # groups alerts sharing a correlation window

    created_at: int = field(default_factory=now)
    updated_at: int = field(default_factory=now)
    last_seen_at: int = field(default_factory=now)
    acknowledged_at: Optional[int] = None
    resolved_at: Optional[int] = None

    signal_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        status = str(self.status)
        if status not in VALID_ALERT_STATUSES:
            status = AlertStatus.NEW.value
        object.__setattr__(self, "status", status)
        sev = str(self.severity)
        if sev not in VALID_SEVERITIES:
            sev = Severity.MEDIUM.value
        object.__setattr__(self, "severity", sev)
        object.__setattr__(self, "title", clean_str(self.title, MAX_LABEL_LEN) or "")
        object.__setattr__(self, "summary", clean_str(self.summary, MAX_REASON_LEN) or "")
        object.__setattr__(self, "chat_id", int(self.chat_id or 0))
        object.__setattr__(self, "hit_count", max(1, int(self.hit_count or 1)))
        if self.signal_id and self.signal_id not in self.signal_ids:
            object.__setattr__(self, "signal_ids", [self.signal_id] + list(self.signal_ids))

    def can_transition_to(self, new_status: str) -> bool:
        return new_status in ALERT_TRANSITIONS.get(self.status, set())

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_row(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id, "chat_id": self.chat_id,
            "correlation_id": self.correlation_id, "signal_id": self.signal_id,
            "dedup_key": self.dedup_key, "title": self.title, "summary": self.summary,
            "severity": self.severity, "priority_band": self.priority_band,
            "priority_score": self.priority_score, "status": self.status,
            "assignee_hash": self.assignee_hash, "hit_count": self.hit_count,
            "group_id": self.group_id, "created_at": self.created_at,
            "updated_at": self.updated_at, "last_seen_at": self.last_seen_at,
            "acknowledged_at": self.acknowledged_at, "resolved_at": self.resolved_at,
            "signal_ids": json_dump(self.signal_ids), "metadata": json_dump(self.metadata),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "Alert":
        row = dict(row)
        return cls(
            alert_id=row.get("alert_id") or gen_id("alt"),
            chat_id=int(row.get("chat_id") or 0),
            correlation_id=row.get("correlation_id") or new_correlation_id(),
            signal_id=row.get("signal_id", ""), dedup_key=row.get("dedup_key", ""),
            title=row.get("title", ""), summary=row.get("summary", ""),
            severity=row.get("severity", Severity.MEDIUM.value),
            priority_band=row.get("priority_band", "P3"),
            priority_score=float(row.get("priority_score") or 0.0),
            status=row.get("status", AlertStatus.NEW.value),
            assignee_hash=row.get("assignee_hash"),
            hit_count=int(row.get("hit_count") or 1),
            group_id=row.get("group_id"),
            created_at=int(row.get("created_at") or now()),
            updated_at=int(row.get("updated_at") or now()),
            last_seen_at=int(row.get("last_seen_at") or now()),
            acknowledged_at=row.get("acknowledged_at"),
            resolved_at=row.get("resolved_at"),
            signal_ids=list(json_load(row.get("signal_ids")) or []),
            metadata=json_load(row.get("metadata")),
            schema_version=int(row.get("schema_version") or SCHEMA_VERSION),
        )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id, "chat_id": self.chat_id,
            "correlation_id": self.correlation_id, "title": self.title,
            "severity": self.severity, "priority_band": self.priority_band,
            "priority_score": self.priority_score, "status": self.status,
            "hit_count": self.hit_count,
        }
