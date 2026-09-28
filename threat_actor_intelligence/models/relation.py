"""
threat_actor_intelligence.models.relation — typed, explainable relationships.

A ``Relationship`` is the edge between any two CTI objects (actor→campaign,
campaign→malware, malware→technique, ioc→infrastructure, report→actor, ...). It
is never bare: it carries the *signal* that produced it, the evidence backing
it, and a confidence. This is what makes the graph and correlation output
explainable — "why is this actor linked to this campaign?" is answered by the
relationship's ``signal`` + ``evidence``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .confidence import ConfidenceModel
from .evidence import EvidenceRef


class ObjectType(str, Enum):
    ACTOR = "actor"
    CAMPAIGN = "campaign"
    MALWARE = "malware"
    INFRASTRUCTURE = "infrastructure"
    IOC = "ioc"
    REPORT = "report"
    TECHNIQUE = "technique"
    TACTIC = "tactic"
    SOFTWARE = "software"
    VICTIM = "victim"
    COUNTRY = "country"
    INDUSTRY = "industry"

    @classmethod
    def coerce(cls, raw: Any) -> "ObjectType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.IOC


class RelationType(str, Enum):
    ATTRIBUTED_TO = "attributed_to"          # campaign/report -> actor (as reported)
    USES = "uses"                            # actor/campaign -> malware/technique
    TARGETS = "targets"                      # actor/campaign -> victim/industry/country
    ASSOCIATED_WITH = "associated_with"      # generic co-occurrence
    COMMUNICATES_WITH = "communicates_with"  # malware/ioc -> infrastructure
    RESOLVES_TO = "resolves_to"              # domain -> ip
    HOSTS = "hosts"                          # infrastructure -> ioc/malware
    INDICATES = "indicates"                  # ioc -> malware/campaign
    MENTIONS = "mentions"                    # report -> any
    VARIANT_OF = "variant_of"                # malware -> malware
    ALIAS_OF = "alias_of"                    # object -> object (same, per source)
    MITIGATES = "mitigates"                  # mitigation -> technique
    SUBTECHNIQUE_OF = "subtechnique_of"      # technique -> technique
    OVERLAPS = "overlaps"                    # infrastructure/ioc shared signal

    @classmethod
    def coerce(cls, raw: Any) -> "RelationType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.ASSOCIATED_WITH


@dataclass
class Relationship:
    src_type: ObjectType
    src_id: str
    rel_type: RelationType
    dst_type: ObjectType
    dst_id: str
    signal: str = ""                 # human-readable reason (the "why")
    weight: float = 1.0
    confidence: Optional[ConfidenceModel] = None
    evidence: List[EvidenceRef] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0

    def __post_init__(self) -> None:
        self.src_type = ObjectType.coerce(self.src_type)
        self.dst_type = ObjectType.coerce(self.dst_type)
        self.rel_type = RelationType.coerce(self.rel_type)

    @property
    def id(self) -> str:
        return hashlib.sha256(
            f"{self.src_type.value}:{self.src_id}|{self.rel_type.value}|"
            f"{self.dst_type.value}:{self.dst_id}".encode("utf-8")
        ).hexdigest()[:24]

    @property
    def score(self) -> float:
        return self.confidence.score if self.confidence else self.weight

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "src_type": self.src_type.value, "src_id": self.src_id,
            "rel_type": self.rel_type.value,
            "dst_type": self.dst_type.value, "dst_id": self.dst_id,
            "signal": self.signal, "weight": round(self.weight, 4),
            "confidence": self.confidence.to_dict() if self.confidence else None,
            "evidence": [e.to_dict() for e in self.evidence],
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Relationship":
        return cls(
            src_type=ObjectType.coerce(d.get("src_type")),
            src_id=str(d.get("src_id", "")),
            rel_type=RelationType.coerce(d.get("rel_type")),
            dst_type=ObjectType.coerce(d.get("dst_type")),
            dst_id=str(d.get("dst_id", "")),
            signal=str(d.get("signal", "")),
            weight=float(d.get("weight", 1.0) or 1.0),
            confidence=(ConfidenceModel.from_dict(d["confidence"])
                        if d.get("confidence") else None),
            evidence=[EvidenceRef.from_dict(e) for e in d.get("evidence", []) or []],
            first_seen=float(d.get("first_seen", 0.0) or 0.0),
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
        )


__all__ = ["ObjectType", "RelationType", "Relationship"]
