"""
cybersecurity_intelligence.models.contradiction — conflicts, surfaced not resolved.

When two sources disagree — vendor A attributes a campaign to APT29, vendor B to
a different cluster; one report calls a CVE actively exploited, another says
"no public exploitation observed" — the platform's job is to *show both* with
their sources, never to silently pick a winner (spec §25). A
:class:`Contradiction` records the conflicting positions, each tied back to the
claim and sources that assert it, so a reader can adjudicate with the evidence in
front of them.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class ContradictionType(str, Enum):
    """The dimension on which sources conflict."""
    ATTRIBUTION = "attribution"            # who did it
    TIMELINE = "timeline"                  # when it happened
    MALWARE_NAMING = "malware_naming"      # what the malware is called
    IOC = "ioc"                            # indicator value/status conflict
    CVE_EXPLOITATION = "cve_exploitation"  # exploited vs not / PoC vs in-the-wild
    TARGET = "target"                      # who/what was targeted
    INFRASTRUCTURE = "infrastructure"      # infra ownership/association
    SEVERITY = "severity"                  # severity/impact rating conflict
    OTHER = "other"

    @classmethod
    def coerce(cls, raw: Any) -> "ContradictionType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.OTHER


@dataclass
class ContradictionPosition:
    """One side of a contradiction: a value asserted by one or more sources."""
    value: str
    claim_id: str = ""
    sources: List[str] = field(default_factory=list)
    band: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"value": self.value, "claim_id": self.claim_id,
                "sources": list(self.sources), "band": self.band}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ContradictionPosition":
        return cls(value=str(d.get("value", "")),
                   claim_id=str(d.get("claim_id", "")),
                   sources=list(d.get("sources", []) or []),
                   band=str(d.get("band", "")))


@dataclass
class Contradiction:
    """A detected conflict between two or more positions on the same subject."""
    contradiction_type: ContradictionType
    subject_key: str                       # the ClaimSubject.key() in conflict
    summary: str
    positions: List[ContradictionPosition] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.contradiction_type = ContradictionType.coerce(self.contradiction_type)

    @property
    def contradiction_id(self) -> str:
        vals = "|".join(sorted(p.value.lower() for p in self.positions))
        basis = f"{self.contradiction_type.value}|{self.subject_key.lower()}|{vals}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]

    @property
    def claim_ids(self) -> List[str]:
        return [p.claim_id for p in self.positions if p.claim_id]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contradiction_id": self.contradiction_id,
            "contradiction_type": self.contradiction_type.value,
            "subject_key": self.subject_key,
            "summary": self.summary,
            "positions": [p.to_dict() for p in self.positions],
            "claim_ids": self.claim_ids,
            "detected_at": self.detected_at,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Contradiction":
        return cls(
            contradiction_type=ContradictionType.coerce(d.get("contradiction_type")),
            subject_key=str(d.get("subject_key", "")),
            summary=str(d.get("summary", "")),
            positions=[ContradictionPosition.from_dict(p)
                       for p in d.get("positions", []) or []],
            detected_at=float(d.get("detected_at", time.time()) or time.time()),
            detail=dict(d.get("detail", {}) or {}),
        )


__all__ = ["ContradictionType", "ContradictionPosition", "Contradiction"]
