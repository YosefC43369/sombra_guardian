"""
cve_tracker.intelligence — risk, prioritization, correlation, change detection.

The intelligence layer turns an enriched record into operational signals without
ever fabricating a CVSS score (rule §17). Public helpers:

  * :func:`prioritize`     — set the internal priority band/score/reasons
  * :func:`assess_risk`    — bundle the factual risk indicators
  * :func:`diff`           — change detection between two record versions
  * :class:`CorrelationEngine` — indexed 'related CVEs' queries
"""

from .scoring import compute_score, compute_breakdown, ScoreBreakdown
from .prioritization import (
    prioritize,
    band_for_score,
    priority_label_thai,
    order_for_dispatch,
    event_priority_rank,
)
from .risk import assess_risk, RiskIndicators
from .exposure import assess as assess_exposure, ExposureProfile
from .correlation import CorrelationEngine, CorrelationResult
from .similarity import record_similarity, is_likely_same, rank_related
from .change_detection import diff, events_for, should_notify_update

__all__ = [
    "compute_score", "compute_breakdown", "ScoreBreakdown",
    "prioritize", "band_for_score", "priority_label_thai",
    "order_for_dispatch", "event_priority_rank",
    "assess_risk", "RiskIndicators",
    "assess_exposure", "ExposureProfile",
    "CorrelationEngine", "CorrelationResult",
    "record_similarity", "is_likely_same", "rank_related",
    "diff", "events_for", "should_notify_update",
]
