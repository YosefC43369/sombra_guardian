"""
threat_actor_intelligence.models.threat_actor — the ThreatActor entity.

An actor is a structured, evidence-anchored record of a *publicly reported*
threat group. The design encodes two hard rules from the core objective:

  1. Identity is never inferred from aliases alone. Aliases are stored as
     ``Alias`` objects, each carrying the source that reported the naming. Two
     actors sharing an alias are *candidates* for merge, surfaced by the alias
     resolver — never merged automatically.
  2. Every field that could be mistaken for attribution (campaigns, malware,
     techniques, victimology) is a reference plus evidence, and the actor's
     confidence is recomputed from that evidence, never set by hand.

The actor id is a stable slug of the canonical name so re-ingestion is
idempotent; the confidence is derived from the evidence bundle via the shared
``confidence_from_evidence`` path.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .confidence import ConfidenceModel, confidence_from_evidence
from .evidence import EvidenceBundle, EvidenceRef
from .victimology import Victimology


def slugify(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "unknown"


class ActorType(str, Enum):
    NATION_STATE = "nation-state"
    CYBERCRIME = "cybercrime"
    HACKTIVIST = "hacktivist"
    RANSOMWARE = "ransomware"
    INSIDER = "insider"
    TERRORIST = "terrorist"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "ActorType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class Alias:
    """A name for an actor as assigned by a specific source (vendor naming is
    notoriously divergent — APT29 / Cozy Bear / Midnight Blizzard / Nobelium)."""
    name: str
    source: str = ""                 # who assigned/uses this name
    source_url: str = ""
    kind: str = "vendor"             # vendor | apt | self | campaign | historical

    @property
    def normalized(self) -> str:
        return re.sub(r"\s+", " ", (self.name or "").strip()).lower()

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "normalized": self.normalized,
                "source": self.source, "source_url": self.source_url,
                "kind": self.kind}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Alias":
        return cls(name=str(d.get("name", "")), source=str(d.get("source", "")),
                   source_url=str(d.get("source_url", "")),
                   kind=str(d.get("kind", "vendor")))


@dataclass
class ThreatActor:
    canonical_name: str
    actor_type: ActorType = ActorType.UNKNOWN
    description: str = ""
    aliases: List[Alias] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    suspected_origin: str = ""       # country as *reported*, never inferred
    motivations: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)          # campaign ids
    malware_families: List[str] = field(default_factory=list)   # family ids
    infrastructure: List[str] = field(default_factory=list)     # infra ids
    techniques: List[str] = field(default_factory=list)         # ATT&CK ids
    software: List[str] = field(default_factory=list)           # ATT&CK S#### ids
    attack_group_id: str = ""        # ATT&CK G#### if mapped
    victimology: Victimology = field(default_factory=Victimology)
    references: List[str] = field(default_factory=list)
    report_ids: List[str] = field(default_factory=list)
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    confidence: Optional[ConfidenceModel] = None
    actor_id: str = ""

    def __post_init__(self) -> None:
        self.actor_type = ActorType.coerce(self.actor_type)
        if isinstance(self.evidence, list):
            self.evidence = EvidenceBundle.from_list(self.evidence)
        if isinstance(self.victimology, dict):
            self.victimology = Victimology.from_dict(self.victimology)
        self.aliases = [a if isinstance(a, Alias) else Alias.from_dict(a)
                        for a in self.aliases]
        if not self.actor_id:
            self.actor_id = slugify(self.canonical_name)
        if not self.victimology.subject_id:
            self.victimology.subject_id = self.actor_id

    # -- aliases ---------------------------------------------------------- #

    def alias_names(self) -> List[str]:
        return sorted({a.normalized for a in self.aliases if a.normalized})

    def add_alias(self, alias: Alias) -> bool:
        if alias.normalized == slugify(self.canonical_name).replace("-", " "):
            return False
        for a in self.aliases:
            if a.normalized == alias.normalized:
                return False
        self.aliases.append(alias)
        return True

    def all_names(self) -> List[str]:
        names = {self.canonical_name.lower()} | set(self.alias_names())
        return sorted(n for n in names if n)

    # -- reference merges (idempotent, de-duplicated) --------------------- #

    def link(self, field_name: str, value: str) -> None:
        lst = getattr(self, field_name, None)
        if isinstance(lst, list) and value and value not in lst:
            lst.append(value)

    # -- confidence ------------------------------------------------------- #

    def recompute_confidence(self, *, now: Optional[float] = None) -> ConfidenceModel:
        now = now if now is not None else time.time()
        self.confidence = confidence_from_evidence(self.evidence, now=now)
        # Actor identity always carries the alias-is-not-identity limitation.
        self.confidence.add_limitation(
            "Actor grouping reflects public naming; it does not assert that all "
            "cited activity was performed by a single legal or natural person.",
            "critical")
        return self.confidence

    def touch(self, when: float) -> None:
        self.first_seen = when if not self.first_seen else min(self.first_seen, when)
        self.last_seen = max(self.last_seen, when)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id, "canonical_name": self.canonical_name,
            "actor_type": self.actor_type.value, "description": self.description,
            "aliases": [a.to_dict() for a in self.aliases],
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "suspected_origin": self.suspected_origin,
            "motivations": list(self.motivations),
            "campaigns": list(self.campaigns),
            "malware_families": list(self.malware_families),
            "infrastructure": list(self.infrastructure),
            "techniques": list(self.techniques), "software": list(self.software),
            "attack_group_id": self.attack_group_id,
            "victimology": self.victimology.to_dict(),
            "references": list(self.references), "report_ids": list(self.report_ids),
            "evidence": self.evidence.to_list(),
            "confidence": self.confidence.to_dict() if self.confidence else None,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ThreatActor":
        actor = cls(
            canonical_name=str(d.get("canonical_name", "")),
            actor_type=ActorType.coerce(d.get("actor_type")),
            description=str(d.get("description", "")),
            aliases=[Alias.from_dict(a) for a in d.get("aliases", []) or []],
            first_seen=float(d.get("first_seen", 0.0) or 0.0),
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
            suspected_origin=str(d.get("suspected_origin", "")),
            motivations=list(d.get("motivations", []) or []),
            campaigns=list(d.get("campaigns", []) or []),
            malware_families=list(d.get("malware_families", []) or []),
            infrastructure=list(d.get("infrastructure", []) or []),
            techniques=list(d.get("techniques", []) or []),
            software=list(d.get("software", []) or []),
            attack_group_id=str(d.get("attack_group_id", "")),
            victimology=Victimology.from_dict(d.get("victimology", {}) or {}),
            references=list(d.get("references", []) or []),
            report_ids=list(d.get("report_ids", []) or []),
            evidence=EvidenceBundle.from_list(d.get("evidence", []) or []),
            actor_id=str(d.get("actor_id", "")),
        )
        if d.get("confidence"):
            actor.confidence = ConfidenceModel.from_dict(d["confidence"])
        return actor


__all__ = ["ThreatActor", "ActorType", "Alias", "slugify"]
