"""
news_intelligence.models.campaign — a campaign as tracked across the news corpus.

``CampaignNews`` merges reports about the same campaign while *preserving
independent sources* and *tracking differing claims* (contradictions are recorded,
never auto-resolved). Backs the Campaign News Profile / Campaign Report.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .evidence import EvidenceBundle


def normalize_campaign_name(raw: str) -> str:
    return re.sub(r"\s+", " ", (raw or "").strip())


def campaign_key(name: str) -> str:
    return "cmp:" + hashlib.sha256(
        normalize_campaign_name(name).lower().encode("utf-8")).hexdigest()[:16]


@dataclass
class DifferingClaim:
    """Two sources making incompatible statements about the campaign — recorded,
    never resolved by the engine."""
    field: str                          # e.g. "attribution", "first_seen_date"
    claim_a: str = ""
    source_a: str = ""
    claim_b: str = ""
    source_b: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DifferingClaim":
        return cls(field=str(d.get("field", "")), claim_a=str(d.get("claim_a", "")),
                   source_a=str(d.get("source_a", "")),
                   claim_b=str(d.get("claim_b", "")),
                   source_b=str(d.get("source_b", "")))


@dataclass
class CampaignNews:
    name: str
    aliases: List[str] = field(default_factory=list)
    article_ids: List[str] = field(default_factory=list)
    actor_names: List[str] = field(default_factory=list)
    malware_names: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    targeted_sectors: List[str] = field(default_factory=list)
    targeted_countries: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    differing_claims: List[DifferingClaim] = field(default_factory=list)
    first_reported: float = 0.0
    last_reported: float = 0.0
    mention_count: int = 0
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    confidence: Optional[Dict[str, Any]] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = normalize_campaign_name(self.name)

    @property
    def key(self) -> str:
        return campaign_key(self.name)

    @property
    def independent_report_count(self) -> int:
        return self.evidence.distinct_count()

    def add_differing_claim(self, claim: DifferingClaim) -> None:
        self.differing_claims.append(claim)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("evidence", None)
        d.pop("differing_claims", None)
        d["evidence"] = self.evidence.to_list()
        d["differing_claims"] = [c.to_dict() for c in self.differing_claims]
        d["key"] = self.key
        d["independent_report_count"] = self.independent_report_count
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CampaignNews":
        obj = cls(
            name=str(d.get("name", "")),
            aliases=list(d.get("aliases", []) or []),
            article_ids=list(d.get("article_ids", []) or []),
            actor_names=list(d.get("actor_names", []) or []),
            malware_names=list(d.get("malware_names", []) or []),
            cve_ids=list(d.get("cve_ids", []) or []),
            targeted_sectors=list(d.get("targeted_sectors", []) or []),
            targeted_countries=list(d.get("targeted_countries", []) or []),
            mitre_techniques=list(d.get("mitre_techniques", []) or []),
            iocs=list(d.get("iocs", []) or []),
            first_reported=float(d.get("first_reported", 0.0) or 0.0),
            last_reported=float(d.get("last_reported", 0.0) or 0.0),
            mention_count=int(d.get("mention_count", 0) or 0),
            confidence=d.get("confidence"),
            detail=dict(d.get("detail", {}) or {}),
        )
        obj.differing_claims = [DifferingClaim.from_dict(c)
                                for c in d.get("differing_claims", []) or []]
        obj.evidence = EvidenceBundle.from_list(d.get("evidence", []) or [])
        return obj


__all__ = ["CampaignNews", "DifferingClaim", "normalize_campaign_name",
           "campaign_key"]
