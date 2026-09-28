"""
threat_actor_intelligence.models.victimology — targeting observed in public
reporting only.

Victimology is where a CTI system most easily overreaches, so this model is
constrained by construction: it records *targeting as described by a cited
public source* — a sector, an industry, a country, an organization type, an
observation window and the source — and never an undisclosed victim, a named
private individual, or an inference of who "must" have been hit. Every
``VictimObservation`` requires an ``EvidenceRef``; the store rejects one without.

Country and industry vocabularies are normalized (ISO-3166 alpha-2 for
countries, a small controlled sector list) so victimology across reports
aggregates cleanly, while the free-text ``as_reported`` preserves the source's
exact wording.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .evidence import EvidenceRef


# A compact controlled sector vocabulary (aligned loosely with common CTI
# taxonomies). Free text maps into the nearest bucket; unknown stays "other".
SECTORS: Dict[str, List[str]] = {
    "government": ["government", "public sector", "ministry", "federal", "military",
                   "defense", "defence", "diplomatic", "embassy"],
    "financial": ["financial", "finance", "bank", "banking", "insurance",
                  "fintech", "payment", "cryptocurrency", "exchange"],
    "healthcare": ["healthcare", "health", "hospital", "medical", "pharma",
                   "pharmaceutical", "biotech"],
    "energy": ["energy", "oil", "gas", "utilities", "power", "electric", "nuclear"],
    "technology": ["technology", "tech", "software", "it", "saas", "cloud",
                   "semiconductor", "telecom", "telecommunications"],
    "manufacturing": ["manufacturing", "industrial", "automotive", "aerospace",
                      "chemical", "engineering"],
    "education": ["education", "university", "academic", "school", "research"],
    "retail": ["retail", "e-commerce", "ecommerce", "hospitality", "consumer"],
    "transportation": ["transportation", "logistics", "shipping", "aviation",
                       "maritime", "rail"],
    "media": ["media", "news", "press", "entertainment", "journalism"],
    "ngo": ["ngo", "non-profit", "nonprofit", "civil society", "activist",
            "human rights"],
    "critical_infrastructure": ["critical infrastructure", "water", "scada", "ics",
                                "ot"],
}
_SECTOR_LOOKUP = {kw: sector for sector, kws in SECTORS.items() for kw in kws}


def normalize_sector(text: str) -> str:
    low = (text or "").strip().lower()
    if not low:
        return "other"
    if low in SECTORS:
        return low
    for kw, sector in _SECTOR_LOOKUP.items():
        if kw in low:
            return sector
    return "other"


class TargetingConfidence(str, Enum):
    CONFIRMED = "confirmed"          # source states victim was compromised
    TARGETED = "targeted"            # source states victim was targeted/attempted
    REPORTED = "reported"            # source lists as a target of interest
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "TargetingConfidence":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.REPORTED


@dataclass
class VictimObservation:
    """One targeting datum from one public source."""
    country: str = ""                # ISO-3166 alpha-2, normalized upstream
    region: str = ""                 # e.g. "Southeast Asia", free text
    sector: str = ""                 # normalized bucket
    industry: str = ""               # finer free-text industry as reported
    organization_type: str = ""      # e.g. "government agency", "MSP"
    as_reported: str = ""            # source's exact wording
    targeting: TargetingConfidence = TargetingConfidence.REPORTED
    observed_from: float = 0.0
    observed_to: float = 0.0
    evidence: Optional[EvidenceRef] = None

    def __post_init__(self) -> None:
        self.targeting = TargetingConfidence.coerce(self.targeting)
        if self.country:
            self.country = self.country.strip().upper()[:2]
        if self.sector:
            self.sector = normalize_sector(self.sector)
        elif self.industry:
            self.sector = normalize_sector(self.industry)

    @property
    def id(self) -> str:
        key = f"{self.country}|{self.sector}|{self.industry}|{self.organization_type}"
        src = self.evidence.ref_id if self.evidence else ""
        return hashlib.sha256(f"{key}|{src}".encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "country": self.country, "region": self.region,
                "sector": self.sector, "industry": self.industry,
                "organization_type": self.organization_type,
                "as_reported": self.as_reported, "targeting": self.targeting.value,
                "observed_from": self.observed_from, "observed_to": self.observed_to,
                "evidence": self.evidence.to_dict() if self.evidence else None}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VictimObservation":
        ev = d.get("evidence")
        return cls(country=str(d.get("country", "")), region=str(d.get("region", "")),
                   sector=str(d.get("sector", "")), industry=str(d.get("industry", "")),
                   organization_type=str(d.get("organization_type", "")),
                   as_reported=str(d.get("as_reported", "")),
                   targeting=TargetingConfidence.coerce(d.get("targeting")),
                   observed_from=float(d.get("observed_from", 0.0) or 0.0),
                   observed_to=float(d.get("observed_to", 0.0) or 0.0),
                   evidence=EvidenceRef.from_dict(ev) if ev else None)


@dataclass
class Victimology:
    """Aggregated targeting picture for an actor or campaign."""
    subject_id: str = ""
    observations: List[VictimObservation] = field(default_factory=list)

    def add(self, obs: VictimObservation) -> None:
        seen = {o.id for o in self.observations}
        if obs.id not in seen:
            self.observations.append(obs)

    def countries(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for o in self.observations:
            if o.country:
                out[o.country] = out.get(o.country, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def sectors(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for o in self.observations:
            if o.sector:
                out[o.sector] = out.get(o.sector, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    def to_dict(self) -> Dict[str, Any]:
        return {"subject_id": self.subject_id,
                "countries": self.countries(), "sectors": self.sectors(),
                "observations": [o.to_dict() for o in self.observations]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Victimology":
        return cls(subject_id=str(d.get("subject_id", "")),
                   observations=[VictimObservation.from_dict(o)
                                 for o in d.get("observations", []) or []])


__all__ = ["SECTORS", "normalize_sector", "TargetingConfidence",
           "VictimObservation", "Victimology"]
