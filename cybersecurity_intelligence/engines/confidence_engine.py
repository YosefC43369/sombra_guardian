"""
cybersecurity_intelligence.engines.confidence_engine — explainable confidence.

Confidence scoring lives in exactly one place so every claim is scored
identically. The heavy lifting — noisy-OR corroboration across independent
sources, source-trust, recency decay, sample saturation, contradiction penalty —
is already implemented and battle-tested in
``threat_actor_intelligence.models.confidence.confidence_from_evidence``. This
engine calls it and then applies the CTI-analysis layer's *claim-type ceiling*:
a single-source REPORTED claim can never be "very high" no matter how trusted the
one source is, an INFERRED claim is capped below "high", a DISPUTED claim is
capped in the low/moderate band. The ceiling and the reason are recorded as a
``Limitation`` so the number is always accompanied by why it is what it is.

Confidence here means *evidence quality*, never *certainty of guilt* — the
standing CTI limitations from the upstream module ride along on every score.
"""

from __future__ import annotations

import time
from typing import List, Optional, Sequence

from threat_actor_intelligence.models.confidence import (
    ConfidenceModel,
    Limitation,
    band_for,
    confidence_from_evidence,
)

from ..models.claim import Claim, ClaimType


class ConfidenceEngine:
    """Computes and attaches an explainable ``ConfidenceModel`` to a claim."""

    def __init__(self, *, now: Optional[float] = None) -> None:
        self._now = now

    def _clock(self) -> float:
        return self._now if self._now is not None else time.time()

    def score_claim(self, claim: Claim,
                    *, contradicting: Optional[Sequence[str]] = None,
                    extra_limitations: Optional[Sequence[Limitation]] = None
                    ) -> ConfidenceModel:
        """Compute confidence for ``claim`` and attach it. Returns the model.

        ``contradicting`` names the providers whose evidence conflicts with this
        claim (the contradiction engine supplies them); each subtracts the
        upstream contradiction penalty.
        """
        now = self._clock()
        cm = confidence_from_evidence(
            claim.evidence, now=now, contradicting=contradicting,
            extra_limitations=list(extra_limitations or []))

        ceiling = claim.claim_type.confidence_ceiling
        if cm.score > ceiling:
            cm.add_limitation(
                f"Confidence capped at {ceiling:.2f} because this is a "
                f"{claim.claim_type.value.upper()} claim, not an independently "
                f"corroborated observation.", "caution")
            cm.score = ceiling
            cm.band = band_for(cm.score)
            cm.factors["claim_type_ceiling"] = round(ceiling, 4)

        claim.confidence = cm
        return cm

    def score_all(self, claims: Sequence[Claim]) -> List[Claim]:
        """Score a batch of claims in place; returns the same list."""
        for c in claims:
            self.score_claim(c)
        return list(claims)


__all__ = ["ConfidenceEngine"]
