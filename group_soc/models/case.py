"""
group_soc/models/case.py — a SOC Case and its notes.

A case is an analyst's workspace: it ties together alerts, an assignee, notes and
evidence links while an investigation runs. Distinct from bb_case.py (bug-bounty
findings) — this is group-security operational casework.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..constants import (
    CaseStatus, VALID_CASE_STATUSES, CASE_TRANSITIONS,
    Severity, VALID_SEVERITIES, MAX_LABEL_LEN, MAX_NOTE_LEN,
)
from ..util import now, gen_id, json_dump, json_load, clean_str
from ..version import SCHEMA_VERSION


@dataclass(frozen=True)
class CaseNote:
    note_id: str = field(default_factory=lambda: gen_id("note"))
    case_id: str = ""
    ts: int = field(default_factory=now)
    author_hash: Optional[str] = None
    text: str = ""

    def __post_init__(self):
        object.__setattr__(self, "text", clean_str(self.text, MAX_NOTE_LEN) or "")

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_row(self) -> Dict[str, Any]:
        return {"note_id": self.note_id, "case_id": self.case_id, "ts": self.ts,
                "author_hash": self.author_hash, "text": self.text}

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "CaseNote":
        row = dict(row)
        return cls(note_id=row.get("note_id") or gen_id("note"),
                   case_id=row.get("case_id", ""), ts=int(row.get("ts") or now()),
                   author_hash=row.get("author_hash"), text=row.get("text", ""))


@dataclass(frozen=True)
class Case:
    case_id: str = field(default_factory=lambda: gen_id("case"))
    chat_id: int = 0
    title: str = ""
    summary: str = ""
    severity: str = Severity.MEDIUM.value
    status: str = CaseStatus.OPEN.value
    assignee_hash: Optional[str] = None
    opened_by_hash: Optional[str] = None

    alert_ids: List[str] = field(default_factory=list)
    incident_id: Optional[str] = None

    created_at: int = field(default_factory=now)
    updated_at: int = field(default_factory=now)
    closed_at: Optional[int] = None

    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        status = str(self.status)
        if status not in VALID_CASE_STATUSES:
            status = CaseStatus.OPEN.value
        object.__setattr__(self, "status", status)
        sev = str(self.severity)
        if sev not in VALID_SEVERITIES:
            sev = Severity.MEDIUM.value
        object.__setattr__(self, "severity", sev)
        object.__setattr__(self, "title", clean_str(self.title, MAX_LABEL_LEN) or "")
        object.__setattr__(self, "chat_id", int(self.chat_id or 0))

    def can_transition_to(self, new_status: str) -> bool:
        return new_status in CASE_TRANSITIONS.get(self.status, set())

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_row(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id, "chat_id": self.chat_id, "title": self.title,
            "summary": self.summary, "severity": self.severity, "status": self.status,
            "assignee_hash": self.assignee_hash, "opened_by_hash": self.opened_by_hash,
            "alert_ids": json_dump(self.alert_ids), "incident_id": self.incident_id,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "closed_at": self.closed_at, "metadata": json_dump(self.metadata),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "Case":
        row = dict(row)
        return cls(
            case_id=row.get("case_id") or gen_id("case"),
            chat_id=int(row.get("chat_id") or 0), title=row.get("title", ""),
            summary=row.get("summary", ""),
            severity=row.get("severity", Severity.MEDIUM.value),
            status=row.get("status", CaseStatus.OPEN.value),
            assignee_hash=row.get("assignee_hash"),
            opened_by_hash=row.get("opened_by_hash"),
            alert_ids=list(json_load(row.get("alert_ids")) or []),
            incident_id=row.get("incident_id"),
            created_at=int(row.get("created_at") or now()),
            updated_at=int(row.get("updated_at") or now()),
            closed_at=row.get("closed_at"),
            metadata=json_load(row.get("metadata")),
            schema_version=int(row.get("schema_version") or SCHEMA_VERSION),
        )
