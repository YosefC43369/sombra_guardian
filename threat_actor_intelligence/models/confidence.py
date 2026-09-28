"""
threat_actor_intelligence.models.confidence — explainable confidence + epistemics.

This is the module that keeps the engine honest. No correlation, attribution or
timeline claim leaves the subsystem as a bare number or a flat assertion. Every
analytical output carries:

  * an ``AssertionKind`` — OBSERVED (present in a public source), CORRELATED
    (two observed facts co-occur, no cause claimed), INFERRED (an interpretation)
    or UNKNOWN (the public data cannot establish it). Reports render the label
    verbatim so a reader can never mistake a shared-infrastructure coincidence
    for an attribution.
  * a ``ConfidenceModel`` — a 0..1 score folded from four *evidence-quality*
    dimensions (corroboration across independent sources, source trust, recency,
    sample size) with the full factor breakdown attached. Confidence here means
    *evidence quality*, never *certainty of guilt*.
  * ``supporting`` and ``contradicting`` source lists.
  * ``Limitation`` lines, including the standing CTI limitations that every
    result must carry (no attribution beyond public sources; aliases are not
    identity; absence of a signal is not absence of activity).

The scoring is deterministic and auditable: identical inputs yield an identical
score and breakdown, because these feed evidence-graded intelligence reports.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .evidence import EvidenceBundle, EvidenceRef, SOURCE_CLASS_WEIGHT, SourceClass


# ---- tunable, inspectable model constants ---------------------------------- #
SAMPLE_SATURATION = 6.0          # independent citations at which sample factor ~1
RECENCY_HALF_LIFE_DAYS = 365.0   # a citation's recency weight halves each year
CONTRADICTION_PENALTY = 0.20     # per contradicting source, subtracted
DAY = 86400.0


class AssertionKind(str, Enum):
    OBSERVED = "OBSERVED"
    CORRELATED = "CORRELATED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def coerce(cls, raw: Any) -> "AssertionKind":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().upper())
        except ValueError:
            return cls.UNKNOWN


# ATT&CK-style confidence bands, mapped onto our 0..1 score.
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


# Standing CTI limitations appended to every confidence model. These encode the
# core objective's guardrails so no report can omit them.
STANDING_LIMITATIONS: List[Tuple[str, str]] = [
    ("Based only on publicly available reporting; absence of a source is not "
     "evidence that an activity did not occur.", "caution"),
    ("Aliases and name overlaps are tracked as reported by public sources and "
     "are never treated as proof that two actors are the same identity.",
     "critical"),
    ("No attribution of criminal responsibility is asserted beyond what the "
     "cited public sources themselves state.", "critical"),
]


@dataclass
class Limitation:
    text: str
    severity: str = "info"       # info | caution | critical

    def to_dict(self) -> Dict[str, Any]:
        return {"text": self.text, "severity": self.severity}


def _recency_factor(age_days: float, half_life: float = RECENCY_HALF_LIFE_DAYS) -> float:
    if age_days <= 0:
        return 1.0
    return 0.5 ** (age_days / max(1e-6, half_life))


@dataclass
class ConfidenceModel:
    """The reasons behind a confidence score — never just the number.

    ``compute`` folds four evidence dimensions into a 0..1 score:
      * corroboration — noisy-OR across the trust weights of the *distinct*
        supporting providers (independent confirmation raises confidence);
      * source_trust — the best single supporting source's class weight;
      * recency — decay from the freshest supporting citation's age;
      * sample — saturating function of the number of distinct citations.
    Contradicting sources subtract a fixed penalty each."""

    supporting_signals: List[str] = field(default_factory=list)
    contradicting_signals: List[str] = field(default_factory=list)
    source_weights: List[float] = field(default_factory=list)   # per distinct src
    freshest_age_days: float = 0.0
    sample_size: int = 0
    limitations: List[Limitation] = field(default_factory=list)
    score: float = 0.0
    band: str = "very low"
    factors: Dict[str, float] = field(default_factory=dict)

    def compute(self) -> "ConfidenceModel":
        weights = [max(0.0, min(1.0, w)) for w in self.source_weights] or [0.5]
        # noisy-OR corroboration across independent sources
        prod = 1.0
        for w in weights:
            prod *= (1.0 - w)
        corroboration = 1.0 - prod
        source_trust = max(weights)
        recency = _recency_factor(self.freshest_age_days)
        sample_f = 1.0 - math.exp(-self.sample_size / SAMPLE_SATURATION)

        self.factors = {
            "corroboration": round(corroboration, 4),
            "source_trust": round(source_trust, 4),
            "recency": round(recency, 4),
            "sample": round(sample_f, 4),
        }
        core = (0.40 * corroboration + 0.25 * source_trust +
                0.20 * recency + 0.15 * sample_f)
        penalty = CONTRADICTION_PENALTY * len(self.contradicting_signals)
        self.factors["contradiction_penalty"] = round(penalty, 4)

        self.score = max(0.0, min(1.0, core - penalty))
        self.band = band_for(self.score)

        have = {lim.text for lim in self.limitations}
        for text, sev in STANDING_LIMITATIONS:
            if text not in have:
                self.limitations.append(Limitation(text, sev))
        return self

    def add_limitation(self, text: str, severity: str = "info") -> None:
        if text not in {l.text for l in self.limitations}:
            self.limitations.append(Limitation(text, severity))

    @property
    def score_100(self) -> int:
        return int(round(self.score * 100))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "score_100": self.score_100,
            "band": self.band,
            "supporting_signals": list(self.supporting_signals),
            "contradicting_signals": list(self.contradicting_signals),
            "sample_size": self.sample_size,
            "freshest_age_days": round(self.freshest_age_days, 2),
            "factors": self.factors,
            "limitations": [l.to_dict() for l in self.limitations],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ConfidenceModel":
        cm = cls(
            supporting_signals=list(d.get("supporting_signals", []) or []),
            contradicting_signals=list(d.get("contradicting_signals", []) or []),
            sample_size=int(d.get("sample_size", 0) or 0),
            freshest_age_days=float(d.get("freshest_age_days", 0.0) or 0.0),
        )
        cm.score = float(d.get("score", 0.0) or 0.0)
        cm.band = str(d.get("band", band_for(cm.score)))
        cm.factors = dict(d.get("factors", {}) or {})
        cm.limitations = [Limitation(x.get("text", ""), x.get("severity", "info"))
                          for x in d.get("limitations", []) or []]
        return cm


def confidence_from_evidence(bundle: EvidenceBundle, *, now: float,
                             contradicting: Optional[Sequence[str]] = None,
                             extra_limitations: Optional[Sequence[Limitation]] = None
                             ) -> ConfidenceModel:
    """Build a computed ``ConfidenceModel`` directly from an ``EvidenceBundle``.

    The distinct-provider trust weights drive corroboration; the freshest
    citation drives recency; the citation count drives sample size. This is the
    single path every entity/correlation uses so confidence is always computed
    identically from the same evidence."""
    by_provider: Dict[str, float] = {}
    for ref in bundle:
        by_provider[ref.provider] = max(by_provider.get(ref.provider, 0.0),
                                        ref.weight)
    weights = list(by_provider.values()) or [0.5]
    latest = bundle.latest()
    age_days = ((now - latest) / DAY) if latest else RECENCY_HALF_LIFE_DAYS
    cm = ConfidenceModel(
        supporting_signals=sorted(by_provider.keys()),
        contradicting_signals=list(contradicting or []),
        source_weights=weights,
        freshest_age_days=max(0.0, age_days),
        sample_size=len(bundle),
        limitations=list(extra_limitations or []),
    )
    return cm.compute()


@dataclass
class Assertion:
    """A single labelled analytical statement backed by evidence — the atom of
    every report. The engine never says "APT-X operated campaign Y"; it returns
    an Assertion(kind=CORRELATED, statement=..., confidence=..., evidence=[...])
    so the epistemic status and the sources are always on the page."""

    statement: str
    kind: AssertionKind = AssertionKind.OBSERVED
    confidence: Optional[ConfidenceModel] = None
    evidence: List[EvidenceRef] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.kind = AssertionKind.coerce(self.kind)

    @property
    def score(self) -> float:
        return self.confidence.score if self.confidence else 0.0

    def render(self) -> str:
        conf = f" (confidence {self.score:.2f} {self.confidence.band})" \
            if self.confidence else ""
        return f"[{self.kind.value}] {self.statement}{conf}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "statement": self.statement,
            "confidence": self.confidence.to_dict() if self.confidence else None,
            "evidence": [e.to_dict() for e in self.evidence],
            "tags": list(self.tags),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Assertion":
        return cls(
            statement=str(d.get("statement", "")),
            kind=AssertionKind.coerce(d.get("kind")),
            confidence=(ConfidenceModel.from_dict(d["confidence"])
                        if d.get("confidence") else None),
            evidence=[EvidenceRef.from_dict(e) for e in d.get("evidence", []) or []],
            tags=list(d.get("tags", []) or []),
            detail=dict(d.get("detail", {}) or {}),
        )


__all__ = ["AssertionKind", "ConfidenceModel", "Assertion", "Limitation",
           "band_for", "confidence_from_evidence", "STANDING_LIMITATIONS"]
