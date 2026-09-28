"""
geo_osint.models.evidence — the provenance record behind every geographic claim.

The engine's central discipline (spec §43) is that *no geographic conclusion
stands without evidence*. Every coordinate, every "this entity is in this city",
every ASN-to-region mapping carries at least one :class:`Evidence` object naming:

  * the **source** (which public dataset / API / document said so),
  * the **source_url** (where a reviewer can re-check it),
  * a **timestamp** (when it was observed),
  * a **confidence** in [0, 1] (how much the source is trusted for this claim),
  * a **precision** note (how exact the underlying datum is), and
  * explicit **limitations** (what this evidence does *not* prove).

This is what keeps the engine honest: an IP-geolocation "city" is evidence from a
provider at provider precision, never a physical-presence fact; a WHOIS country is
a registration signal, not a hosting location. The limitations field is where
that distinction is written down and carried into the report.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ConfidenceBand(str, Enum):
    """Human-readable buckets over the numeric confidence, for reports."""

    CONFIRMED = "confirmed"      # >= 0.90 : multiple independent public sources
    HIGH = "high"                # >= 0.70
    MEDIUM = "medium"            # >= 0.45
    LOW = "low"                  # >= 0.20
    SPECULATIVE = "speculative"  # <  0.20

    @classmethod
    def of(cls, confidence: float) -> "ConfidenceBand":
        if confidence >= 0.90:
            return cls.CONFIRMED
        if confidence >= 0.70:
            return cls.HIGH
        if confidence >= 0.45:
            return cls.MEDIUM
        if confidence >= 0.20:
            return cls.LOW
        return cls.SPECULATIVE


@dataclass
class Evidence:
    """One provenance record supporting a geographic assertion."""

    source: str                                  # e.g. "wikidata", "rdap", "geonames"
    claim: str                                   # what this evidence supports
    confidence: float = 0.5
    source_url: str = ""
    observed_at: float = field(default_factory=time.time)
    precision: str = ""                          # free text, e.g. "city-centroid"
    limitations: str = ""                         # what it does NOT prove
    raw: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    @property
    def band(self) -> ConfidenceBand:
        return ConfidenceBand.of(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "claim": self.claim,
            "confidence": round(self.confidence, 4),
            "band": self.band.value,
            "source_url": self.source_url,
            "observed_at": self.observed_at,
            "observed_iso": _iso(self.observed_at),
            "precision": self.precision,
            "limitations": self.limitations,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(
            source=str(d.get("source", "")),
            claim=str(d.get("claim", "")),
            confidence=float(d.get("confidence", 0.5)),
            source_url=str(d.get("source_url", "")),
            observed_at=float(d.get("observed_at", time.time())),
            precision=str(d.get("precision", "")),
            limitations=str(d.get("limitations", "")),
            raw=dict(d.get("raw", {})),
        )


class EvidenceLedger:
    """A small collection helper: aggregates evidence for one assertion and
    computes a combined confidence with the noisy-OR rule.

    Noisy-OR is the right combiner for *independent* corroborating sources: two
    weak-but-independent signals should raise confidence, never average it down.
    Callers that know two pieces of evidence are *not* independent (same upstream
    dataset re-served by two APIs) should add only one.
    """

    def __init__(self) -> None:
        self._items: List[Evidence] = []

    def add(self, evidence: Evidence) -> "EvidenceLedger":
        self._items.append(evidence)
        return self

    def extend(self, items: List[Evidence]) -> "EvidenceLedger":
        self._items.extend(items)
        return self

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    @property
    def items(self) -> List[Evidence]:
        return list(self._items)

    @property
    def sources(self) -> List[str]:
        seen: List[str] = []
        for e in self._items:
            if e.source not in seen:
                seen.append(e.source)
        return seen

    def combined_confidence(self) -> float:
        """Noisy-OR over independent sources: 1 - prod(1 - c_i)."""
        product = 1.0
        for e in self._items:
            product *= (1.0 - e.confidence)
        return round(1.0 - product, 4)

    @property
    def band(self) -> ConfidenceBand:
        return ConfidenceBand.of(self.combined_confidence())

    def to_list(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._items]


def _iso(epoch: float) -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
    except (OSError, ValueError, OverflowError):
        return ""
