"""
behavioral_intelligence.scoring — explainable scores.

Activity-level, cross-account consistency, anomaly (deviation-from-baseline) and
confidence scores. Every score exposes its underlying features, is deterministic,
and is descriptive: none of them is a judgement of a person, and the anomaly
score in particular is a deviation measure, never a threat/criminality score.
"""

from . import activity_score, consistency_score, anomaly_score, confidence_score
from .activity_score import score_activity, ActivityScore
from .consistency_score import compare_accounts
from .anomaly_score import score_from_deviations
from .confidence_score import (make_confidence, aggregate_confidence,
                               source_count, band_for)

__all__ = [
    "activity_score", "consistency_score", "anomaly_score", "confidence_score",
    "score_activity", "ActivityScore", "compare_accounts",
    "score_from_deviations", "make_confidence", "aggregate_confidence",
    "source_count", "band_for",
]
