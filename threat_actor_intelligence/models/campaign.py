"""
threat_actor_intelligence.models.campaign — the Campaign entity.

Campaigns are modelled *separately* from actors on purpose: public reporting
often describes a campaign (a bounded set of activity with shared TTPs/infra/
timing) before, or without, confident attribution to a named actor. Keeping them
distinct lets the engine hold "campaign X used malware Y against sector Z"
firmly, while the actor link stays an explicit, evidence-graded relationship that
can be absent or low-confidence.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .confidence import ConfidenceModel, confidence_from_evidence
from .evidence import EvidenceBundle
from .threat_actor import Alias, slugify
from .victimology import Victimology


@dataclass
class Campaign:
    campaign_name: str
    summary: str = ""
    aliases: List[Alias] = field(default_factory=list)
    first_observed: float = 0.0
    last_observed: float = 0.0
    actors: List[str] = field(default_factory=list)             # actor ids (as reported)
    malware_families: List[str] = field(default_factory=list)   # family ids
    infrastructure: List[str] = field(default_factory=list)     # infra ids
    iocs: List[str] = field(default_factory=list)               # ioc ids
    techniques: List[str] = field(default_factory=list)         # ATT&CK ids
    victimology: Victimology = field(default_factory=Victimology)
    attack_campaign_id: str = ""     # ATT&CK C#### if mapped
    references: List[str] = field(default_factory=list)
    report_ids: List[str] = field(default_factory=list)
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    confidence: Optional[ConfidenceModel] = None
    campaign_id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.evidence, list):
            self.evidence = EvidenceBundle.from_list(self.evidence)
        if isinstance(self.victimology, dict):
            self.victimology = Victimology.from_dict(self.victimology)
        self.aliases = [a if isinstance(a, Alias) else Alias.from_dict(a)
                        for a in self.aliases]
        if not self.campaign_id:
            self.campaign_id = "camp-" + slugify(self.campaign_name)
        if not self.victimology.subject_id:
            self.victimology.subject_id = self.campaign_id

    def alias_names(self) -> List[str]:
        return sorted({a.normalized for a in self.aliases if a.normalized})

    def add_alias(self, alias: Alias) -> bool:
        for a in self.aliases:
            if a.normalized == alias.normalized:
                return False
        self.aliases.append(alias)
        return True

    def link(self, field_name: str, value: str) -> None:
        lst = getattr(self, field_name, None)
        if isinstance(lst, list) and value and value not in lst:
            lst.append(value)

    def touch(self, when: float) -> None:
        self.first_observed = when if not self.first_observed \
            else min(self.first_observed, when)
        self.last_observed = max(self.last_observed, when)

    def duration_days(self) -> float:
        if self.first_observed and self.last_observed:
            return round((self.last_observed - self.first_observed) / 86400.0, 1)
        return 0.0

    def recompute_confidence(self, *, now: Optional[float] = None) -> ConfidenceModel:
        now = now if now is not None else time.time()
        self.confidence = confidence_from_evidence(self.evidence, now=now)
        return self.confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id, "campaign_name": self.campaign_name,
            "summary": self.summary, "aliases": [a.to_dict() for a in self.aliases],
            "first_observed": self.first_observed, "last_observed": self.last_observed,
            "duration_days": self.duration_days(),
            "actors": list(self.actors), "malware_families": list(self.malware_families),
            "infrastructure": list(self.infrastructure), "iocs": list(self.iocs),
            "techniques": list(self.techniques),
            "victimology": self.victimology.to_dict(),
            "attack_campaign_id": self.attack_campaign_id,
            "references": list(self.references), "report_ids": list(self.report_ids),
            "evidence": self.evidence.to_list(),
            "confidence": self.confidence.to_dict() if self.confidence else None,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Campaign":
        c = cls(
            campaign_name=str(d.get("campaign_name", "")),
            summary=str(d.get("summary", "")),
            aliases=[Alias.from_dict(a) for a in d.get("aliases", []) or []],
            first_observed=float(d.get("first_observed", 0.0) or 0.0),
            last_observed=float(d.get("last_observed", 0.0) or 0.0),
            actors=list(d.get("actors", []) or []),
            malware_families=list(d.get("malware_families", []) or []),
            infrastructure=list(d.get("infrastructure", []) or []),
            iocs=list(d.get("iocs", []) or []),
            techniques=list(d.get("techniques", []) or []),
            victimology=Victimology.from_dict(d.get("victimology", {}) or {}),
            attack_campaign_id=str(d.get("attack_campaign_id", "")),
            references=list(d.get("references", []) or []),
            report_ids=list(d.get("report_ids", []) or []),
            evidence=EvidenceBundle.from_list(d.get("evidence", []) or []),
            campaign_id=str(d.get("campaign_id", "")),
        )
        if d.get("confidence"):
            c.confidence = ConfidenceModel.from_dict(d["confidence"])
        return c


__all__ = ["Campaign"]
