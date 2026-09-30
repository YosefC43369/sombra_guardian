"""
cybersecurity_intelligence.constants — enumerations and tunable model constants.

Everything analytic in this package is deterministic and inspectable: the same
inputs always yield the same grade, confidence and assessment. That is only true
if the knobs live in one place, named, with a documented meaning. This module is
that place. Nothing here reaches the network or reads the environment (that is
``config.py``); these are the intrinsic constants of the analytic model.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Tuple


class ReliabilityGrade(str, Enum):
    """Coarse, explainable grade for a *source* — not a truth verdict.

    A HIGH grade means "this publisher has, historically and structurally, been a
    dependable reporter of technical fact"; it never means the specific claim is
    true. LOW does not mean "false", it means "treat with corroboration". UNKNOWN
    is a first-class value: an un-graded source is not silently assumed mediocre.
    """
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "ReliabilityGrade":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def from_score(cls, score: float) -> "ReliabilityGrade":
        """Map a 0..1 reliability score to a grade. Below the UNKNOWN floor the
        score is too weakly supported to grade at all."""
        if score >= HIGH_GRADE_FLOOR:
            return cls.HIGH
        if score >= MEDIUM_GRADE_FLOOR:
            return cls.MEDIUM
        if score >= LOW_GRADE_FLOOR:
            return cls.LOW
        return cls.UNKNOWN


class Priority(str, Enum):
    """Operational priority of a finding/alert. Priority describes *how much
    attention a defender should give this*, never the intent or guilt of any
    actor."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def coerce(cls, raw: Any) -> "Priority":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.INFORMATIONAL

    @property
    def rank(self) -> int:
        return {
            Priority.CRITICAL: 4,
            Priority.HIGH: 3,
            Priority.MEDIUM: 2,
            Priority.LOW: 1,
            Priority.INFORMATIONAL: 0,
        }[self]


class ProductType(str, Enum):
    """The four classic CTI product tiers. One input often yields several."""
    STRATEGIC = "strategic"      # long-term trends for leadership
    OPERATIONAL = "operational"  # campaigns/actors/infrastructure for defenders
    TACTICAL = "tactical"        # TTP/IOC/detection context for the SOC
    TECHNICAL = "technical"      # hashes/domains/IPs/certs/CVE detail

    @classmethod
    def coerce(cls, raw: Any) -> "ProductType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.TECHNICAL


class AssessmentStatementType(str, Enum):
    """The epistemic register of a single line in an assessment. Keeping these
    separate is the whole point of the assessment engine: a reader must never
    mistake an analyst's inference for a source-reported fact."""
    FACT = "fact"                       # independently verifiable / definitional
    SOURCE_CLAIM = "source_claim"       # a source asserts this; we relay it
    ANALYTIC_INFERENCE = "analytic_inference"   # our interpretation of evidence
    UNCERTAINTY = "uncertainty"         # a named gap / unresolved question

    @classmethod
    def coerce(cls, raw: Any) -> "AssessmentStatementType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNCERTAINTY


# --------------------------------------------------------------------------- #
# Reliability grade thresholds (0..1 score → grade). Tunable, documented.
# --------------------------------------------------------------------------- #
HIGH_GRADE_FLOOR = 0.75
MEDIUM_GRADE_FLOOR = 0.55
LOW_GRADE_FLOOR = 0.30

# --------------------------------------------------------------------------- #
# Corroboration / independence
# --------------------------------------------------------------------------- #
# Number of *independent* sources at/above which a claim may be labelled
# CORROBORATED rather than merely REPORTED.
CORROBORATION_MIN_INDEPENDENT_SOURCES = 2

# Two citations are treated as NOT independent when they share the same
# registrable source host, or when one explicitly references the other, or when
# both are pure aggregators/feeds re-publishing upstream data. Aggregator and
# feed classes are down-weighted so a wire re-print does not manufacture
# corroboration.
NON_INDEPENDENT_SOURCE_CLASSES = ("aggregator", "feed")

# --------------------------------------------------------------------------- #
# Claim-type confidence modulation. A claim's *type* caps or shapes how much
# confidence the evidence can produce. These are ceilings/multipliers applied on
# top of the evidence-derived score from ConfidenceModel, never replacements for
# it. Order matters only in that DISPUTED and UNKNOWN are hard caps.
# --------------------------------------------------------------------------- #
CLAIM_TYPE_CONFIDENCE_CEILING = {
    "observed": 1.00,       # directly present in a source; evidence decides
    "corroborated": 1.00,   # multiple independent sources; evidence decides
    "reported": 0.75,       # single-source assertion; cannot be "very high"
    "inferred": 0.60,       # analytic interpretation; capped below "high"
    "disputed": 0.45,       # sources conflict; capped in "low/moderate"
    "unknown": 0.25,        # insufficient evidence; floor band only
}

# --------------------------------------------------------------------------- #
# Data-freshness bands (age in days → label). Used by change/freshness logic.
# --------------------------------------------------------------------------- #
FRESHNESS_BANDS: List[Tuple[float, str]] = [
    (7.0, "fresh"),       # <= 7 days
    (30.0, "recent"),     # <= 30 days
    (180.0, "aging"),     # <= 180 days
    (float("inf"), "stale"),
]

# Confidence bands re-exported for the assessment layer (mirrors the numeric
# bands in threat_actor_intelligence.models.confidence.BANDS but named for CTI
# products). The upstream module remains the single source of the numeric map.
CONFIDENCE_LABELS = ("very low", "low", "moderate", "high", "very high")


def freshness_label(age_days: float) -> str:
    """Map an age in days to a freshness label. Negative/zero ages are fresh."""
    if age_days <= 0:
        return "fresh"
    for ceiling, label in FRESHNESS_BANDS:
        if age_days <= ceiling:
            return label
    return "stale"


__all__ = [
    "ReliabilityGrade",
    "Priority",
    "ProductType",
    "AssessmentStatementType",
    "HIGH_GRADE_FLOOR",
    "MEDIUM_GRADE_FLOOR",
    "LOW_GRADE_FLOOR",
    "CORROBORATION_MIN_INDEPENDENT_SOURCES",
    "NON_INDEPENDENT_SOURCE_CLASSES",
    "CLAIM_TYPE_CONFIDENCE_CEILING",
    "FRESHNESS_BANDS",
    "CONFIDENCE_LABELS",
    "freshness_label",
]
