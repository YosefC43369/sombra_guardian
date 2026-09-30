"""
group_soc/incidents/classification.py — classify an incident from its signals/alerts.

Maps the producers of the contributing signals to an IncidentClass, and aggregates
their risk dimensions (max severity/impact, noisy-OR confidence) into one incident-level
RiskDimensions. Pure functions, no storage.
"""

from __future__ import annotations

from typing import Iterable, List

from ..models.signal import SecuritySignal
from ..models.severity import RiskDimensions
from ..constants import IncidentClass
from ..prioritization.confidence import combine_confidence


_PRODUCER_CLASS = (
    ("threshold:join_burst", IncidentClass.RAID.value),
    ("campaign", IncidentClass.SPAM_CAMPAIGN.value),
    ("sequence:join_then_link", IncidentClass.MALICIOUS_LINK.value),
    ("rule:ioc_match", IncidentClass.IOC_EXPOSURE.value),
    ("entity:shared_indicator", IncidentClass.COORDINATED_ACTIVITY.value),
    ("behavioral", IncidentClass.COORDINATED_ACTIVITY.value),
    ("sequence:join_leave_churn", IncidentClass.COORDINATED_ACTIVITY.value),
)


def classify(signals: Iterable[SecuritySignal]) -> str:
    signals = list(signals)
    # first producer substring that matches wins (ordered by specificity above)
    for needle, klass in _PRODUCER_CLASS:
        for s in signals:
            if needle in (s.producer or ""):
                return klass
    return IncidentClass.OTHER.value


def aggregate_dimensions(signals: Iterable[SecuritySignal]) -> RiskDimensions:
    signals = list(signals)
    if not signals:
        return RiskDimensions()
    dims = [s.dimensions for s in signals]
    return RiskDimensions(
        severity=max(d.severity for d in dims),
        confidence=combine_confidence(d.confidence for d in dims),
        impact=max(d.impact for d in dims),
        urgency=max(d.urgency for d in dims),
        exposure=max(d.exposure for d in dims),
        persistence=max(d.persistence for d in dims),
    )
