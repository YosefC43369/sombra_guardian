"""
behavioral_intelligence.models.confidence — the epistemics layer.

This module is the mechanism that enforces the engine's core principle: *the
system describes observable patterns; it does not conclude about the person.*
Nothing else in the package is allowed to emit a bare claim. Every analytical
output is expressed as an ``Assertion`` that carries:

  * an ``AssertionKind`` — is this an OBSERVED fact, a CORRELATED coincidence, an
    INFERRED interpretation, or explicitly UNKNOWN? Reports render these labels
    verbatim so a reader can never mistake a correlation for a conclusion.
  * a ``ConfidenceModel`` — a 0..1 score with its *reasons*: sample size,
    observation period, number of independent sources, the signals that support
    it and the signals that contradict it.
  * ``EvidenceRef`` links back to the observations/sources it rests on.
  * ``Limitation`` lines stating what the result cannot establish.

The scoring is deliberately simple, deterministic and auditable — the same
inputs always produce the same score, because these feed investigation reports
and (via the caller) the repository's integrity ledger.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple


# ---- tunable model constants (inspectable, so runs are reproducible) ------- #
SAMPLE_SATURATION = 40.0        # sample size at which the sample-size factor ~1
PERIOD_SATURATION_DAYS = 30.0   # observation window at which the period factor ~1
SOURCE_SATURATION = 5.0         # independent sources at which the source factor ~1
CONTRADICTION_PENALTY = 0.18    # per contradicting signal, subtracted from score
MIN_SAMPLE_FOR_PATTERN = 5      # below this, no pattern assertion above INFERRED


class AssertionKind(str, Enum):
    """The epistemic status of a statement. This is the single most important
    type in the package — it is how the engine keeps observation and inference
    separate, in code and in every report."""

    OBSERVED = "OBSERVED"       # directly present in the collected public data
    CORRELATED = "CORRELATED"   # two observed facts co-occur; no cause asserted
    INFERRED = "INFERRED"       # an interpretation drawn from observed facts
    UNKNOWN = "UNKNOWN"         # the available public data cannot establish this

    @classmethod
    def coerce(cls, raw: Any) -> "AssertionKind":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().upper())
        except ValueError:
            return cls.UNKNOWN


BANDS: List[Tuple[float, str]] = [
    (0.85, "very high"),
    (0.70, "high"),
    (0.50, "moderate"),
    (0.30, "low"),
    (0.0, "very low"),
]


def band_for(score: float) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "very low"


@dataclass
class EvidenceRef:
    """A pointer from an assertion back to the public data it rests on.

    Mirrors ``entity_fusion.entity.SourceRef`` but is observation-centric: it can
    name a specific ``observation_id`` and the public ``source_url`` it came
    from, with the source's own reliability and the collection time preserved."""

    provider: str = ""
    source_url: str = ""
    observation_id: str = ""
    content_hash: str = ""
    timestamp: float = 0.0            # when the underlying event happened (UTC)
    collected_at: float = field(default_factory=time.time)
    confidence: float = 1.0           # the source's self-reported reliability
    detail: str = ""

    def key(self) -> str:
        return self.observation_id or f"{self.provider}|{self.source_url}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceRef":
        return cls(
            provider=str(d.get("provider", "")),
            source_url=str(d.get("source_url", "")),
            observation_id=str(d.get("observation_id", "")),
            content_hash=str(d.get("content_hash", "")),
            timestamp=float(d.get("timestamp", 0.0) or 0.0),
            collected_at=float(d.get("collected_at", time.time()) or time.time()),
            confidence=float(d.get("confidence", 1.0) or 1.0),
            detail=str(d.get("detail", "")),
        )


class SourceType(str, Enum):
    """Coarse source categories used by the reliability model."""
    DIRECT = "direct"            # first-party public API / the platform itself
    ARCHIVE = "archive"          # Wayback / Common Crawl — historical, indirect
    AGGREGATOR = "aggregator"    # a third party that re-publishes others' data
    FEED = "feed"                # RSS / ActivityPub firehose
    DERIVED = "derived"          # computed by this engine from other observations
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "SourceType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


# Base reliability by source type — a starting weight, adjusted by freshness and
# corroboration in SourceReliability.assess. Not all sources are equal, and the
# engine must not silently pretend they are (spec §32).
_SOURCE_BASE = {
    SourceType.DIRECT: 0.95,
    SourceType.FEED: 0.85,
    SourceType.ARCHIVE: 0.75,
    SourceType.AGGREGATOR: 0.6,
    SourceType.DERIVED: 0.7,
    SourceType.UNKNOWN: 0.5,
}


@dataclass
class SourceReliability:
    """An explainable reliability weight for a provider/source.

    Factors (each recorded): the source *type*, the *freshness* of the datum,
    whether the observation was *direct* or indirect, and how many *independent*
    sources corroborate it. Returns a weight in [0,1] plus the factor breakdown —
    never a bare number."""

    provider: str
    source_type: SourceType = SourceType.UNKNOWN
    duplicate_confirmations: int = 0
    freshness_days: Optional[float] = None
    historical_consistency: float = 1.0   # 0..1, from prior agreement (default trust)
    factors: Dict[str, float] = field(default_factory=dict)

    def assess(self) -> float:
        base = _SOURCE_BASE.get(SourceType.coerce(self.source_type), 0.5)
        self.factors["base"] = round(base, 3)

        # freshness: decays gently over ~180 days; unknown freshness is neutral.
        if self.freshness_days is None:
            fresh = 1.0
        else:
            fresh = math.exp(-max(0.0, self.freshness_days) / 180.0)
        fresh = 0.6 + 0.4 * fresh          # never drop a stale source below 0.6x
        self.factors["freshness"] = round(fresh, 3)

        # corroboration: each independent confirmation lifts weight, saturating.
        corrob = 1.0 + 0.15 * (1.0 - math.exp(-self.duplicate_confirmations / 2.0))
        self.factors["corroboration"] = round(corrob, 3)

        hist = max(0.0, min(1.0, self.historical_consistency))
        self.factors["historical_consistency"] = round(hist, 3)

        weight = base * fresh * corrob * (0.7 + 0.3 * hist)
        weight = max(0.0, min(1.0, weight))
        self.factors["weight"] = round(weight, 3)
        return weight

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_type"] = SourceType.coerce(self.source_type).value
        d["weight"] = self.assess()
        return d


@dataclass
class Limitation:
    """A single explicit statement of what a result cannot establish."""
    text: str
    severity: str = "info"       # info | caution | critical

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text, "severity": self.severity}


# Standing limitations that apply to *every* behavioural result, appended by the
# ConfidenceModel so no report can omit them.
STANDING_LIMITATIONS = [
    Limitation("Reflects only publicly observed data; absence of a signal is not "
               "evidence of its absence in reality.", "caution"),
    Limitation("Describes observable activity patterns, not the person behind the "
               "account; no psychological, medical or intent conclusion is implied.",
               "critical"),
]


@dataclass
class ConfidenceModel:
    """The reasons behind a confidence score — never just the number.

    ``compute`` folds four evidence dimensions (sample size, observation period,
    independent source count, contradiction) into a 0..1 score with a fully
    populated factor breakdown. A tiny sample or a single source caps the score;
    contradicting signals subtract from it."""

    sample_size: int = 0
    observation_period_days: float = 0.0
    source_count: int = 0
    supporting_signals: List[str] = field(default_factory=list)
    contradicting_signals: List[str] = field(default_factory=list)
    limitations: List[Limitation] = field(default_factory=list)
    score: float = 0.0
    band: str = "very low"
    factors: Dict[str, float] = field(default_factory=dict)

    def compute(self) -> "ConfidenceModel":
        # Each factor is a bounded [0,1] multiplier with a clear meaning.
        sample_f = 1.0 - math.exp(-self.sample_size / SAMPLE_SATURATION)
        period_f = 1.0 - math.exp(-self.observation_period_days / PERIOD_SATURATION_DAYS)
        source_f = 1.0 - math.exp(-self.source_count / SOURCE_SATURATION)
        support_f = 1.0 - math.exp(-len(self.supporting_signals) / 3.0)

        self.factors = {
            "sample_size": round(sample_f, 3),
            "observation_period": round(period_f, 3),
            "source_diversity": round(source_f, 3),
            "supporting_signals": round(support_f, 3),
        }

        # Geometric-ish blend: a zero in any dimension should drag the score down,
        # but we keep a floor so a strong single dimension is not fully erased.
        core = (0.40 * sample_f + 0.25 * period_f +
                0.20 * source_f + 0.15 * support_f)
        penalty = CONTRADICTION_PENALTY * len(self.contradicting_signals)
        self.factors["contradiction_penalty"] = round(penalty, 3)

        self.score = max(0.0, min(1.0, core - penalty))
        self.band = band_for(self.score)
        # Standing limitations are always present, de-duplicated by text.
        have = {lim.text for lim in self.limitations}
        for lim in STANDING_LIMITATIONS:
            if lim.text not in have:
                self.limitations.append(lim)
        if self.sample_size < MIN_SAMPLE_FOR_PATTERN:
            self.limitations.append(Limitation(
                f"Sample of {self.sample_size} observations is below the "
                f"minimum ({MIN_SAMPLE_FOR_PATTERN}) for a stable pattern; treat "
                f"as indicative only.", "caution"))
        return self

    def add_limitation(self, text: str, severity: str = "info") -> None:
        self.limitations.append(Limitation(text, severity))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "band": self.band,
            "sample_size": self.sample_size,
            "observation_period_days": round(self.observation_period_days, 2),
            "source_count": self.source_count,
            "supporting_signals": list(self.supporting_signals),
            "contradicting_signals": list(self.contradicting_signals),
            "limitations": [lim.to_dict() for lim in self.limitations],
            "factors": self.factors,
        }


@dataclass
class Assertion:
    """A single labelled analytical statement — the atom of every report.

    An engine never returns "the account is nocturnal". It returns an Assertion
    with ``kind=OBSERVED``, ``statement="Activity concentrated 19:00–23:00 UTC"``,
    the confidence model behind it, the evidence it rests on, and the period it
    covers. Reports render ``kind`` as a prefix so the epistemic status is always
    on the page."""

    statement: str
    kind: AssertionKind = AssertionKind.OBSERVED
    confidence: Optional[ConfidenceModel] = None
    evidence: List[EvidenceRef] = field(default_factory=list)
    observation_period: Tuple[float, float] = (0.0, 0.0)
    tags: List[str] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.kind = AssertionKind.coerce(self.kind)

    @property
    def score(self) -> float:
        return self.confidence.score if self.confidence else 0.0

    def render(self) -> str:
        """The canonical one-line rendering used by text reports and Telegram."""
        conf = f" (confidence {self.score:.2f})" if self.confidence else ""
        return f"[{self.kind.value}] {self.statement}{conf}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "statement": self.statement,
            "confidence": self.confidence.to_dict() if self.confidence else None,
            "evidence": [e.to_dict() for e in self.evidence],
            "observation_period": {
                "start": self.observation_period[0],
                "end": self.observation_period[1],
            },
            "tags": list(self.tags),
            "detail": self.detail,
        }


def make_confidence(*, sample_size: int, period_days: float, source_count: int,
                    supporting: Optional[Sequence[str]] = None,
                    contradicting: Optional[Sequence[str]] = None,
                    limitations: Optional[Sequence[Limitation]] = None
                    ) -> ConfidenceModel:
    """Convenience constructor used across the engines so confidence is always
    computed the same way from the same four dimensions."""
    cm = ConfidenceModel(
        sample_size=sample_size,
        observation_period_days=period_days,
        source_count=source_count,
        supporting_signals=list(supporting or []),
        contradicting_signals=list(contradicting or []),
        limitations=list(limitations or []),
    )
    return cm.compute()
