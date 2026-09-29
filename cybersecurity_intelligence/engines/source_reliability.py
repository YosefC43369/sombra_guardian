"""
cybersecurity_intelligence.engines.source_reliability — explainable source grading.

Grades *how dependable a publisher is*, and shows every factor that produced the
grade. It never emits an absolute "true"/"false" verdict on a source or a claim
(spec §6); a HIGH grade is "structurally dependable reporter of technical fact",
a LOW grade is "treat with corroboration", UNKNOWN is a real state (not enough to
grade). The grading is deterministic: the same source signals always yield the
same score and the same factor breakdown, because these feed graded reports.

Signals used (all from public metadata, none from the claim's truth):
  * source class base weight (government/standards/vendor/research/community/…),
  * primary vs. secondary publisher,
  * evidence availability (a resolvable URL, an external advisory/CVE id),
  * technical depth (a substantive excerpt rather than a headline),
  * recency of the source's last activity,
  * track record (how many items we have collected from it).
"""

from __future__ import annotations

import math
import time
from typing import List, Optional

from threat_actor_intelligence.models.evidence import (
    EvidenceRef,
    SourceClass,
    SOURCE_CLASS_WEIGHT,
)

from ..constants import ReliabilityGrade
from ..models.source import (
    ReliabilityAssessment,
    ReliabilityFactor,
    SourceRecord,
)

DAY = 86400.0

# Publisher classes that are primary/authoritative reporters vs. re-publishers.
_PRIMARY_CLASSES = {
    SourceClass.GOVERNMENT,
    SourceClass.STANDARDS,
    SourceClass.VENDOR,
    SourceClass.RESEARCH,
}
_SECONDARY_CLASSES = {SourceClass.AGGREGATOR, SourceClass.FEED}

# Contribution weights (documented, tunable). The class base dominates; the rest
# nudge within a band so a single missing URL never flips government to LOW.
_CLASS_BASE_WEIGHT = 0.50
_PRIMARY_BONUS = 0.12
_SECONDARY_PENALTY = 0.08
_URL_BONUS = 0.10
_EXTERNAL_ID_BONUS = 0.05
_DEPTH_BONUS = 0.08
_DEPTH_MIN_CHARS = 200
_RECENCY_MAX = 0.10
_RECENCY_HALFLIFE_DAYS = 180.0
_TRACK_MAX = 0.10
_TRACK_SATURATION = 25.0


class SourceReliabilityEngine:
    """Grades sources and individual citations. Stateless and deterministic."""

    def __init__(self, *, now: Optional[float] = None) -> None:
        self._now = now

    def _clock(self) -> float:
        return self._now if self._now is not None else time.time()

    # -- citation-level ---------------------------------------------------- #

    def grade_ref(self, ref: EvidenceRef) -> ReliabilityAssessment:
        """Grade a single citation from its own metadata."""
        factors: List[ReliabilityFactor] = []
        sc = ref.source_class
        base = SOURCE_CLASS_WEIGHT.get(sc, 0.5) * _CLASS_BASE_WEIGHT
        factors.append(ReliabilityFactor(
            "source_class", base,
            f"{sc.value} publisher (base weight {SOURCE_CLASS_WEIGHT.get(sc, 0.5):.2f})"))

        if sc in _PRIMARY_CLASSES:
            factors.append(ReliabilityFactor(
                "primary_source", _PRIMARY_BONUS,
                "primary/authoritative reporter, not a re-publisher"))
        elif sc in _SECONDARY_CLASSES:
            factors.append(ReliabilityFactor(
                "secondary_source", -_SECONDARY_PENALTY,
                "re-publisher/aggregator; corroborate against the primary"))

        if ref.source_url:
            factors.append(ReliabilityFactor(
                "resolvable_url", _URL_BONUS, "citation points at a public URL"))
        if ref.external_id:
            factors.append(ReliabilityFactor(
                "external_id", _EXTERNAL_ID_BONUS,
                f"anchored to external id {ref.external_id}"))
        if len(ref.excerpt or "") >= _DEPTH_MIN_CHARS:
            factors.append(ReliabilityFactor(
                "technical_depth", _DEPTH_BONUS,
                "substantive excerpt, not just a headline"))

        rec = self._recency_contribution(ref.observed_at or ref.collected_at)
        if rec > 0:
            factors.append(ReliabilityFactor(
                "recency", rec, "recently observed"))

        return self._assemble(factors)

    # -- source-level ------------------------------------------------------ #

    def grade_source(self, source: SourceRecord,
                     *, sample_refs: Optional[List[EvidenceRef]] = None
                     ) -> ReliabilityAssessment:
        """Grade a publisher from its record, optionally sharpened by a sample of
        its citations (their URL/depth availability informs technical depth)."""
        factors: List[ReliabilityFactor] = []
        sc = source.source_class
        base = SOURCE_CLASS_WEIGHT.get(sc, 0.5) * _CLASS_BASE_WEIGHT
        factors.append(ReliabilityFactor(
            "source_class", base,
            f"{sc.value} publisher (base weight {SOURCE_CLASS_WEIGHT.get(sc, 0.5):.2f})"))

        if sc in _PRIMARY_CLASSES:
            factors.append(ReliabilityFactor(
                "primary_source", _PRIMARY_BONUS,
                "primary/authoritative reporter"))
        elif sc in _SECONDARY_CLASSES:
            factors.append(ReliabilityFactor(
                "secondary_source", -_SECONDARY_PENALTY,
                "aggregator/feed; corroborate against the primary"))

        if source.url:
            factors.append(ReliabilityFactor(
                "resolvable_url", _URL_BONUS, "source has a public URL"))

        # technical depth from a sample of the source's citations
        refs = sample_refs or []
        if refs:
            deep = sum(1 for r in refs if len(r.excerpt or "") >= _DEPTH_MIN_CHARS)
            if deep and deep / len(refs) >= 0.5:
                factors.append(ReliabilityFactor(
                    "technical_depth", _DEPTH_BONUS,
                    "most sampled reports carry substantive technical detail"))

        # track record from collected volume (saturating)
        if source.article_count > 0:
            track = _TRACK_MAX * (1.0 - math.exp(-source.article_count / _TRACK_SATURATION))
            factors.append(ReliabilityFactor(
                "track_record", track,
                f"{source.article_count} items collected from this source"))

        rec = self._recency_contribution(source.last_seen)
        if rec > 0:
            factors.append(ReliabilityFactor("recency", rec, "recently active"))

        return self._assemble(factors)

    # -- helpers ----------------------------------------------------------- #

    def _recency_contribution(self, at: float) -> float:
        if not at:
            return 0.0
        age_days = max(0.0, (self._clock() - at) / DAY)
        decay = 0.5 ** (age_days / _RECENCY_HALFLIFE_DAYS)
        return round(_RECENCY_MAX * decay, 4)

    def _assemble(self, factors: List[ReliabilityFactor]) -> ReliabilityAssessment:
        score = max(0.0, min(1.0, sum(f.contribution for f in factors)))
        return ReliabilityAssessment(
            grade=ReliabilityGrade.from_score(score),
            score=round(score, 4),
            factors=factors,
            assessed_at=self._clock(),
        )


__all__ = ["SourceReliabilityEngine"]
