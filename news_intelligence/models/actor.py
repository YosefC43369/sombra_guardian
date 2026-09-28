"""
news_intelligence.models.actor — a threat actor as tracked across the news.

``ActorNews`` aggregates the news corpus for one threat actor. It preserves every
vendor alias *separately* (APT29 / Cozy Bear / Midnight Blizzard / UNC2452 are
tracked as reported names, never collapsed into a single identity without an
evidence-backed alias link) and links into the Threat Actor Intelligence Engine's
actor record when one resolves. Backs the Threat Actor News Profile report.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .evidence import EvidenceBundle

_APT_RE = re.compile(r"(?i)^(apt|unc|ta|fin|temp|dev|g)\s*\d")


def normalize_actor_name(raw: str) -> str:
    s = (raw or "").strip()
    if _APT_RE.match(s):
        return re.sub(r"\s+", "", s).upper()
    return re.sub(r"\s+", " ", s).title()


def actor_key(name: str) -> str:
    return "act:" + hashlib.sha256(
        normalize_actor_name(name).lower().encode("utf-8")).hexdigest()[:16]


@dataclass
class ActorNews:
    name: str
    aliases: List[str] = field(default_factory=list)   # vendor aliases, preserved
    article_ids: List[str] = field(default_factory=list)
    malware_names: List[str] = field(default_factory=list)
    campaign_names: List[str] = field(default_factory=list)
    targeted_sectors: List[str] = field(default_factory=list)
    targeted_countries: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    tai_actor_id: str = ""                # link into threat_actor_intelligence
    first_reported: float = 0.0
    last_reported: float = 0.0
    mention_count: int = 0
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)
    confidence: Optional[Dict[str, Any]] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = normalize_actor_name(self.name)
        self.aliases = sorted({normalize_actor_name(a) for a in self.aliases
                               if normalize_actor_name(a)
                               and normalize_actor_name(a) != self.name})

    @property
    def key(self) -> str:
        return actor_key(self.name)

    @property
    def independent_report_count(self) -> int:
        return self.evidence.distinct_count()

    def add_alias(self, alias: str) -> None:
        a = normalize_actor_name(alias)
        if a and a != self.name and a not in self.aliases:
            self.aliases.append(a)
            self.aliases.sort()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("evidence", None)
        d["evidence"] = self.evidence.to_list()
        d["key"] = self.key
        d["independent_report_count"] = self.independent_report_count
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ActorNews":
        obj = cls(
            name=str(d.get("name", "")),
            aliases=list(d.get("aliases", []) or []),
            article_ids=list(d.get("article_ids", []) or []),
            malware_names=list(d.get("malware_names", []) or []),
            campaign_names=list(d.get("campaign_names", []) or []),
            targeted_sectors=list(d.get("targeted_sectors", []) or []),
            targeted_countries=list(d.get("targeted_countries", []) or []),
            mitre_techniques=list(d.get("mitre_techniques", []) or []),
            cve_ids=list(d.get("cve_ids", []) or []),
            tai_actor_id=str(d.get("tai_actor_id", "")),
            first_reported=float(d.get("first_reported", 0.0) or 0.0),
            last_reported=float(d.get("last_reported", 0.0) or 0.0),
            mention_count=int(d.get("mention_count", 0) or 0),
            confidence=d.get("confidence"),
            detail=dict(d.get("detail", {}) or {}),
        )
        obj.evidence = EvidenceBundle.from_list(d.get("evidence", []) or [])
        return obj


__all__ = ["ActorNews", "normalize_actor_name", "actor_key"]
