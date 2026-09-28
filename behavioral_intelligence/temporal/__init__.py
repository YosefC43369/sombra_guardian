"""
behavioral_intelligence.temporal — the temporal intelligence engine.

Analyses *when* public activity was observed: rate and coverage, hour/weekday/
month distributions and heatmaps, activity bursts, inactivity gaps, statistical
change points (CUSUM / rolling z-score / EWMA), recurring seasonality, and
cross-platform temporal correlation. Every headline finding is emitted as a
labelled ``Assertion`` (OBSERVED / CORRELATED) with confidence and limitations —
the engine describes timing, it never infers a chronotype, location or lifestyle.
"""

from .temporal_engine import TemporalEngine, TemporalResult
from . import (hourly_analysis, daily_analysis, weekly_analysis, monthly_analysis,
               burst_detection, inactivity_detection, change_point, seasonality)
from .seasonality import SeasonalityResult

__all__ = [
    "TemporalEngine", "TemporalResult", "SeasonalityResult",
    "hourly_analysis", "daily_analysis", "weekly_analysis", "monthly_analysis",
    "burst_detection", "inactivity_detection", "change_point", "seasonality",
]
