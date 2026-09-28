"""
news_intelligence.models.confidence — explainable confidence for news intel.

The news engine reuses the CTI confidence machinery verbatim so a correlation
computed from news articles is scored identically to one computed from CTI
reports (same noisy-OR corroboration, same recency decay, same sample
saturation, same standing limitations). This module re-exports the shared
primitives and adds the news-specific standing limitations that every news
conclusion must carry:

  * a news story is a *claim by a publisher*, not a verified fact;
  * corroboration across syndicated copies of one wire story is not independent
    corroboration;
  * attribution stated in a headline is the publisher's, never the engine's.

A self-contained fallback keeps the module importable if the CTI engine is
absent.
"""

from __future__ import annotations

from typing import Any, List, Optional, Sequence, Tuple

try:
    from threat_actor_intelligence.models.confidence import (  # type: ignore
        AssertionKind, ConfidenceModel, Assertion, Limitation, band_for,
        confidence_from_evidence, STANDING_LIMITATIONS,
    )
    _SHARED = True
except Exception:  # pragma: no cover - standalone fallback
    _SHARED = False
    import math
    from dataclasses import dataclass, field
    from enum import Enum
    from .evidence import EvidenceBundle, SourceClass

    SAMPLE_SATURATION = 6.0
    RECENCY_HALF_LIFE_DAYS = 365.0
    CONTRADICTION_PENALTY = 0.20
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

    BANDS: List[Tuple[float, str]] = [
        (0.85, "very high"), (0.70, "high"), (0.50, "moderate"),
        (0.30, "low"), (0.0, "very low"),
    ]

    def band_for(score: float) -> str:
        for floor, name in BANDS:
            if score >= floor:
                return name
        return "very low"

    STANDING_LIMITATIONS: List[Tuple[str, str]] = [
        ("Based only on publicly available reporting; absence of a source is not "
         "evidence that an activity did not occur.", "caution"),
    ]

    @dataclass
    class Limitation:
        text: str
        severity: str = "info"

        def to_dict(self):
            return {"text": self.text, "severity": self.severity}

    def _recency_factor(age_days: float,
                        half_life: float = RECENCY_HALF_LIFE_DAYS) -> float:
        if age_days <= 0:
            return 1.0
        return 0.5 ** (age_days / max(1e-6, half_life))

    @dataclass
    class ConfidenceModel:
        supporting_signals: List[str] = field(default_factory=list)
        contradicting_signals: List[str] = field(default_factory=list)
        source_weights: List[float] = field(default_factory=list)
        freshest_age_days: float = 0.0
        sample_size: int = 0
        limitations: List[Limitation] = field(default_factory=list)
        score: float = 0.0
        band: str = "very low"
        factors: dict = field(default_factory=dict)

        def compute(self) -> "ConfidenceModel":
            weights = [max(0.0, min(1.0, w)) for w in self.source_weights] or [0.5]
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

        def to_dict(self):
            return {
                "score": round(self.score, 4), "score_100": self.score_100,
                "band": self.band,
                "supporting_signals": list(self.supporting_signals),
                "contradicting_signals": list(self.contradicting_signals),
                "sample_size": self.sample_size,
                "freshest_age_days": round(self.freshest_age_days, 2),
                "factors": self.factors,
                "limitations": [l.to_dict() for l in self.limitations],
            }

        @classmethod
        def from_dict(cls, d):
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

    def confidence_from_evidence(bundle, *, now: float,
                                 contradicting: Optional[Sequence[str]] = None,
                                 extra_limitations: Optional[Sequence] = None):
        by_provider = {}
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
        statement: str
        kind: AssertionKind = AssertionKind.OBSERVED
        confidence: Optional[ConfidenceModel] = None
        evidence: list = field(default_factory=list)
        tags: list = field(default_factory=list)
        detail: dict = field(default_factory=dict)

        def __post_init__(self):
            self.kind = AssertionKind.coerce(self.kind)

        @property
        def score(self) -> float:
            return self.confidence.score if self.confidence else 0.0

        def render(self) -> str:
            conf = (f" (confidence {self.score:.2f} {self.confidence.band})"
                    if self.confidence else "")
            return f"[{self.kind.value}] {self.statement}{conf}"

        def to_dict(self):
            return {
                "kind": self.kind.value, "statement": self.statement,
                "confidence": self.confidence.to_dict() if self.confidence else None,
                "evidence": [e.to_dict() for e in self.evidence],
                "tags": list(self.tags), "detail": self.detail,
            }

        @classmethod
        def from_dict(cls, d):
            from .evidence import EvidenceRef
            return cls(
                statement=str(d.get("statement", "")),
                kind=AssertionKind.coerce(d.get("kind")),
                confidence=(ConfidenceModel.from_dict(d["confidence"])
                            if d.get("confidence") else None),
                evidence=[EvidenceRef.from_dict(e)
                          for e in d.get("evidence", []) or []],
                tags=list(d.get("tags", []) or []),
                detail=dict(d.get("detail", {}) or {}),
            )


# News-specific standing limitations, always folded onto a news conclusion in
# addition to the shared CTI limitations.
NEWS_STANDING_LIMITATIONS: List[Tuple[str, str]] = [
    ("A news report is a claim published by an outlet, not an independently "
     "verified fact; treat headlines as reported, not confirmed.", "caution"),
    ("Multiple copies of one wire/syndicated story are not independent "
     "corroboration; corroboration is counted across distinct originating "
     "outlets only.", "critical"),
    ("Any attribution, victim naming or severity wording is the publisher's; "
     "the engine asserts nothing beyond what the cited article states.",
     "critical"),
]


def news_confidence(bundle, *, now: float,
                    contradicting: Optional[Sequence[str]] = None
                    ) -> "ConfidenceModel":
    """Confidence from a news evidence bundle, carrying both the shared and the
    news-specific standing limitations. This is the single scoring path every
    news correlation and profile uses."""
    extra = [Limitation(text, sev) for text, sev in NEWS_STANDING_LIMITATIONS]
    return confidence_from_evidence(bundle, now=now, contradicting=contradicting,
                                    extra_limitations=extra)


__all__ = ["AssertionKind", "ConfidenceModel", "Assertion", "Limitation",
           "band_for", "confidence_from_evidence", "STANDING_LIMITATIONS",
           "NEWS_STANDING_LIMITATIONS", "news_confidence"]
