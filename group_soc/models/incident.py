"""
group_soc/models/incident.py — a SOC Incident.

A SOC incident is a higher-order aggregate: a confirmed or high-confidence security
situation spanning one or more alerts/cases in a chat. When it concerns a specific
member it links to a member_incident id (single source of truth for member custody),
carried in ``member_incident_id`` and populated by the incidents adapter.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..constants import (
    IncidentStatus, VALID_INCIDENT_STATUSES, INCIDENT_TRANSITIONS,
    IncidentClass, VALID_INCIDENT_CLASSES, Severity, VALID_SEVERITIES,
    MAX_LABEL_LEN, MAX_REASON_LEN,
)
from ..util import now, gen_id, json_dump, json_load, clean_str
from ..version import SCHEMA_VERSION
from .severity import RiskDimensions


@dataclass(frozen=True)
class Incident:
    incident_id: str = field(default_factory=lambda: gen_id("inc"))
    chat_id: int = 0
    title: str = ""
    summary: str = ""
    classification: str = IncidentClass.OTHER.value
    severity: str = Severity.HIGH.value
    status: str = IncidentStatus.OPEN.value

    dimensions: RiskDimensions = field(default_factory=RiskDimensions)

    alert_ids: List[str] = field(default_factory=list)
    case_ids: List[str] = field(default_factory=list)
    correlation_ids: List[str] = field(default_factory=list)

    opened_by_hash: Optional[str] = None
    member_incident_id: Optional[int] = None   # bridge to member_incident.py

    created_at: int = field(default_factory=now)
    updated_at: int = field(default_factory=now)
    resolved_at: Optional[int] = None
    resolution: str = ""

    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        status = str(self.status)
        if status not in VALID_INCIDENT_STATUSES:
            status = IncidentStatus.OPEN.value
        object.__setattr__(self, "status", status)
        cls_ = str(self.classification)
        if cls_ not in VALID_INCIDENT_CLASSES:
            cls_ = IncidentClass.OTHER.value
        object.__setattr__(self, "classification", cls_)
        sev = str(self.severity)
        if sev not in VALID_SEVERITIES:
            sev = Severity.HIGH.value
        object.__setattr__(self, "severity", sev)
        object.__setattr__(self, "title", clean_str(self.title, MAX_LABEL_LEN) or "")
        object.__setattr__(self, "summary", clean_str(self.summary, MAX_REASON_LEN) or "")
        object.__setattr__(self, "resolution", clean_str(self.resolution, MAX_REASON_LEN) or "")
        object.__setattr__(self, "chat_id", int(self.chat_id or 0))

    def can_transition_to(self, new_status: str) -> bool:
        return new_status in INCIDENT_TRANSITIONS.get(self.status, set())

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["dimensions"] = self.dimensions.as_dict()
        return d

    def to_row(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id, "chat_id": self.chat_id,
            "title": self.title, "summary": self.summary,
            "classification": self.classification, "severity": self.severity,
            "status": self.status, "dimensions": json_dump(self.dimensions.as_dict()),
            "alert_ids": json_dump(self.alert_ids), "case_ids": json_dump(self.case_ids),
            "correlation_ids": json_dump(self.correlation_ids),
            "opened_by_hash": self.opened_by_hash,
            "member_incident_id": self.member_incident_id,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "resolved_at": self.resolved_at, "resolution": self.resolution,
            "metadata": json_dump(self.metadata), "schema_version": self.schema_version,
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "Incident":
        row = dict(row)
        return cls(
            incident_id=row.get("incident_id") or gen_id("inc"),
            chat_id=int(row.get("chat_id") or 0), title=row.get("title", ""),
            summary=row.get("summary", ""),
            classification=row.get("classification", IncidentClass.OTHER.value),
            severity=row.get("severity", Severity.HIGH.value),
            status=row.get("status", IncidentStatus.OPEN.value),
            dimensions=RiskDimensions.from_dict(json_load(row.get("dimensions"))),
            alert_ids=list(json_load(row.get("alert_ids")) or []),
            case_ids=list(json_load(row.get("case_ids")) or []),
            correlation_ids=list(json_load(row.get("correlation_ids")) or []),
            opened_by_hash=row.get("opened_by_hash"),
            member_incident_id=row.get("member_incident_id"),
            created_at=int(row.get("created_at") or now()),
            updated_at=int(row.get("updated_at") or now()),
            resolved_at=row.get("resolved_at"), resolution=row.get("resolution", ""),
            metadata=json_load(row.get("metadata")),
            schema_version=int(row.get("schema_version") or SCHEMA_VERSION),
        )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id, "chat_id": self.chat_id,
            "title": self.title, "classification": self.classification,
            "severity": self.severity, "status": self.status,
            "alert_count": len(self.alert_ids),
        }
