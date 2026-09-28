"""
behavioral_intelligence.temporal.monthly_analysis — per-month and month-of-year
activity.

Two views: the per-calendar-month (YYYY-MM) count series for long-horizon trend,
and the month-of-year (Jan..Dec) aggregate used by the seasonality detector to
look for recurring annual structure. Both need many months of data to say
anything, so the caller pairs them with sample-size-aware confidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Sequence, Tuple

from ..models.observation import Observation
from ..models.activity import Histogram

_MONTH_LABELS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def monthly_series(observations: Sequence[Observation]) -> Tuple[List[str], List[int]]:
    """Per-YYYY-MM count series, dense over the observed span (zero-filled)."""
    counts: Dict[str, int] = {}
    for o in observations:
        if not o.has_time:
            continue
        counts[o.month_utc] = counts.get(o.month_utc, 0) + 1
    if not counts:
        return ([], [])
    keys = sorted(counts)
    # densify across months
    start_y, start_m = map(int, keys[0].split("-"))
    end_y, end_m = map(int, keys[-1].split("-"))
    labels: List[str] = []
    series: List[int] = []
    y, m = start_y, start_m
    while (y, m) <= (end_y, end_m):
        key = f"{y:04d}-{m:02d}"
        labels.append(key)
        series.append(counts.get(key, 0))
        m += 1
        if m > 12:
            m = 1
            y += 1
    return (labels, series)


def month_of_year_histogram(observations: Sequence[Observation]) -> Histogram:
    """12-bucket month-of-year aggregate (activity summed across all years)."""
    counts = [0] * 12
    for o in observations:
        if not o.has_time:
            continue
        counts[datetime.fromtimestamp(o.timestamp, tz=timezone.utc).month - 1] += 1
    return Histogram(dimension="month_of_year", labels=list(_MONTH_LABELS),
                     counts=counts, total=sum(counts))
