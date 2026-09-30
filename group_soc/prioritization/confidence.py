"""
group_soc/prioritization/confidence.py — confidence aggregation.

When several signals point at the same thing, their confidences combine by
**noisy-OR** (1 - Π(1 - cᵢ)): independent weak signals reinforce, but the result is
still bounded below 1. This is the standard way to fuse independent evidence and is
far better than a max() or a mean() for triage.
"""

from __future__ import annotations

from typing import Iterable

from ..models.severity import clamp01


def combine_confidence(values: Iterable[float]) -> float:
    product = 1.0
    any_val = False
    for v in values:
        any_val = True
        product *= (1.0 - clamp01(v))
    if not any_val:
        return 0.0
    return clamp01(1.0 - product)


def decay_confidence(confidence: float, age_s: float, half_life_s: float = 3600.0) -> float:
    """Exponential decay so a stale signal weighs less. half_life_s default 1h."""
    if half_life_s <= 0:
        return clamp01(confidence)
    factor = 0.5 ** (max(0.0, age_s) / half_life_s)
    return clamp01(confidence * factor)
