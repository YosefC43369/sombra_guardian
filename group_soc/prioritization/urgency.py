"""
group_soc/prioritization/urgency.py — urgency modifiers.

Urgency rises when a condition *repeats* (an alert that keeps re-firing needs
attention sooner) and is highest for fresh signals. These are small, explainable
adjustments applied on top of a signal's base urgency dimension.
"""

from __future__ import annotations

import math

from ..models.severity import clamp01


def urgency_from_repeats(hit_count: int) -> float:
    """Additive urgency in [0, 0.3] that grows (sub-linearly) with repeat count."""
    n = max(1, int(hit_count or 1))
    if n <= 1:
        return 0.0
    return clamp01(min(0.3, 0.1 * math.log2(n) + 0.05))


def apply_urgency(base_urgency: float, hit_count: int = 1) -> float:
    return clamp01(base_urgency + urgency_from_repeats(hit_count))
