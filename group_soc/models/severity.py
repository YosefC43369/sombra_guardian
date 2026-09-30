"""
group_soc/models/severity.py — the multi-dimensional risk model.

The SOC deliberately does NOT collapse risk into a single number at capture time.
A signal carries several orthogonal dimensions; the PriorityEngine combines them
into a normalized priority only when it needs to rank work. This keeps the raw
analytic signals inspectable and avoids a single opaque "score".

Dimensions (each 0.0 – 1.0):
  severity     how bad the *thing itself* is if real
  confidence   how sure we are it is what we think (analytic, NOT proof of intent)
  impact       blast radius on the group if it plays out
  urgency      how time-sensitive the response is
  exposure     how visible/reachable the group is to it right now
  persistence  how likely it is to recur / how sticky it is
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Dict

from ..constants import Severity, SEVERITY_RANK, SEVERITY_ORDER


def clamp01(x: float) -> float:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if v < 0 else 1.0 if v > 1 else v


def severity_to_float(sev: str) -> float:
    """Map a Severity label to a 0..1 magnitude (info=0 .. critical=1)."""
    rank = SEVERITY_RANK.get(str(sev), SEVERITY_RANK[Severity.LOW.value])
    return rank / (len(SEVERITY_ORDER) - 1)


def float_to_severity(x: float) -> str:
    """Inverse of severity_to_float: bucket a 0..1 magnitude to a label."""
    x = clamp01(x)
    idx = round(x * (len(SEVERITY_ORDER) - 1))
    return SEVERITY_ORDER[idx]


@dataclass(frozen=True)
class RiskDimensions:
    severity: float = 0.0
    confidence: float = 0.0
    impact: float = 0.0
    urgency: float = 0.0
    exposure: float = 0.0
    persistence: float = 0.0

    def __post_init__(self):
        # frozen dataclass: clamp via object.__setattr__
        for f in ("severity", "confidence", "impact", "urgency", "exposure", "persistence"):
            object.__setattr__(self, f, clamp01(getattr(self, f)))

    def as_dict(self) -> Dict[str, float]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "RiskDimensions":
        data = data or {}
        return cls(
            severity=data.get("severity", 0.0),
            confidence=data.get("confidence", 0.0),
            impact=data.get("impact", 0.0),
            urgency=data.get("urgency", 0.0),
            exposure=data.get("exposure", 0.0),
            persistence=data.get("persistence", 0.0),
        )


#: default weights for combining dimensions into a priority score.
#: severity and confidence dominate; the rest modulate.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "severity": 0.30,
    "confidence": 0.25,
    "impact": 0.20,
    "urgency": 0.15,
    "exposure": 0.05,
    "persistence": 0.05,
}


@dataclass(frozen=True)
class PriorityScore:
    """Result of combining RiskDimensions. ``score`` is 0..100; ``band`` is a
    coarse P1..P5 label for humans/queues."""
    score: float
    band: str          # P1 (highest) .. P5 (lowest)
    severity_label: str
    weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    def as_dict(self) -> Dict:
        return {
            "score": self.score,
            "band": self.band,
            "severity_label": self.severity_label,
            "weights": dict(self.weights),
        }


# P-band thresholds on the 0..100 score (inclusive lower bound).
_BANDS = (
    (85.0, "P1"),
    (65.0, "P2"),
    (40.0, "P3"),
    (20.0, "P4"),
    (0.0, "P5"),
)


def band_for_score(score: float) -> str:
    for lo, band in _BANDS:
        if score >= lo:
            return band
    return "P5"
