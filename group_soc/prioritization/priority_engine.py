"""
group_soc/prioritization/priority_engine.py — combine dimensions into a priority.

Takes a signal's RiskDimensions, applies context modifiers (impact from metadata,
urgency from repeats), then computes a weighted 0..100 score and a P1..P5 band. The
weights are configurable; the default emphasises severity and confidence.

The output PriorityScore is what the AlertManager stores on an alert and what queues
sort by.
"""

from __future__ import annotations

from typing import Optional

from ..models.signal import SecuritySignal
from ..models.severity import (
    RiskDimensions, PriorityScore, DEFAULT_WEIGHTS, band_for_score, clamp01,
)
from .impact import apply_impact
from .urgency import apply_urgency
from .severity import effective_severity_label


class PriorityEngine:
    def __init__(self, weights: Optional[dict] = None):
        self.weights = dict(weights) if weights else dict(DEFAULT_WEIGHTS)

    def effective_dimensions(self, signal: SecuritySignal, hit_count: int = 1) -> RiskDimensions:
        d = signal.dimensions
        return RiskDimensions(
            severity=d.severity,
            confidence=d.confidence,
            impact=apply_impact(d.impact, signal.metadata),
            urgency=apply_urgency(d.urgency, hit_count),
            exposure=d.exposure,
            persistence=d.persistence,
        )

    def score(self, signal: SecuritySignal, hit_count: int = 1) -> PriorityScore:
        dims = self.effective_dimensions(signal, hit_count)
        total_weight = sum(self.weights.values()) or 1.0
        acc = 0.0
        for dim, weight in self.weights.items():
            acc += clamp01(getattr(dims, dim, 0.0)) * weight
        score = round(100.0 * acc / total_weight, 1)
        return PriorityScore(
            score=score,
            band=band_for_score(score),
            severity_label=effective_severity_label(dims),
            weights=dict(self.weights),
        )
