"""
behavioral_intelligence.temporal.weekly_analysis — day-of-week and ISO-week
activity.

Two views: the 7-bucket weekday histogram (Mon..Sun, UTC) used in the
hour×weekday heatmap and the weekday/weekend split, and the per-ISO-week count
series used to describe medium-term rhythm without over-fitting to single days.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

from ..models.observation import Observation
from ..models.activity import Histogram
from .. import util


def weekday_histogram(observations: Sequence[Observation],
                      tz_offset_hours: float = 0.0) -> Histogram:
    """7-bucket weekday histogram. The tz offset can move an event across the
    midnight boundary, so it is applied before taking the weekday."""
    counts = [0] * 7
    for o in observations:
        if not o.has_time or not o.timestamp_precision.supports_day:
            continue
        if tz_offset_hours:
            shifted = o.timestamp + tz_offset_hours * util.HOUR_SECONDS
            from datetime import datetime, timezone
            wd = datetime.fromtimestamp(shifted, tz=timezone.utc).weekday()
        else:
            wd = o.weekday_utc
        counts[wd] += 1
    return Histogram(dimension="weekday", labels=list(util.WEEKDAY_LABELS),
                     counts=counts, total=sum(counts))


def weekday_weekend_split(observations: Sequence[Observation]) -> Dict[str, int]:
    hist = weekday_histogram(observations)
    weekday = sum(hist.counts[:5])
    weekend = sum(hist.counts[5:])
    return {"weekday": weekday, "weekend": weekend}


def weekly_series(observations: Sequence[Observation]) -> Tuple[List[str], List[int]]:
    """Per-ISO-week (YYYY-Www) count series, dense over the observed span."""
    counts: Dict[str, int] = {}
    for o in observations:
        if not o.has_time or not o.timestamp_precision.supports_day:
            continue
        counts[o.iso_week_utc] = counts.get(o.iso_week_utc, 0) + 1
    if not counts:
        return ([], [])
    labels = sorted(counts)
    return (labels, [counts[k] for k in labels])
