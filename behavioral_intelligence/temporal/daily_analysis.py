"""
behavioral_intelligence.temporal.daily_analysis — per-calendar-day activity.

Produces the per-date count series over the observed window, the count of active
vs. inactive days, and the daily-rate series used downstream by change-point and
burst detection. Days with no observation are materialised as explicit zeros so
the series is gap-free and evenly spaced (required for the statistical detectors).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Sequence, Tuple

from ..models.observation import Observation
from ..models.activity import Histogram
from .. import util


def _date_of(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def daily_counts(observations: Sequence[Observation]) -> Dict[str, int]:
    """Map YYYY-MM-DD -> observation count, using only day-resolvable events."""
    out: Dict[str, int] = {}
    for o in observations:
        if not o.has_time or not o.timestamp_precision.supports_day:
            continue
        out[_date_of(o.timestamp)] = out.get(_date_of(o.timestamp), 0) + 1
    return out


def dense_daily_series(observations: Sequence[Observation]
                       ) -> Tuple[List[str], List[int]]:
    """A gap-free (date, count) series spanning the first to last active day.
    Missing days are zero-filled so the series is uniformly sampled — the
    statistical detectors assume even spacing."""
    counts = daily_counts(observations)
    if not counts:
        return ([], [])
    dates = sorted(counts)
    start = datetime.strptime(dates[0], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    end = datetime.strptime(dates[-1], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    labels: List[str] = []
    series: List[int] = []
    cur = start
    while cur <= end:
        key = cur.strftime("%Y-%m-%d")
        labels.append(key)
        series.append(counts.get(key, 0))
        cur += timedelta(days=1)
    return (labels, series)


def daily_histogram(observations: Sequence[Observation]) -> Histogram:
    labels, series = dense_daily_series(observations)
    return Histogram(dimension="date", labels=labels, counts=series,
                     total=sum(series))


def active_inactive_days(observations: Sequence[Observation]) -> Tuple[int, int]:
    """(active_days, inactive_days) across the observed span. Inactive days are
    calendar days inside the span with zero observed activity."""
    labels, series = dense_daily_series(observations)
    if not series:
        return (0, 0)
    active = sum(1 for v in series if v > 0)
    return (active, len(series) - active)


def rate_statistics(observations: Sequence[Observation]) -> Dict[str, float]:
    """Posts-per-day statistics over the dense series (includes zero days)."""
    _, series = dense_daily_series(observations)
    if not series:
        return {"posts_per_day": 0.0, "posts_per_active_day": 0.0,
                "peak_day": 0.0, "stdev": 0.0}
    active = [v for v in series if v > 0]
    return {
        "posts_per_day": util.mean([float(v) for v in series]),
        "posts_per_active_day": util.mean([float(v) for v in active]) if active else 0.0,
        "peak_day": float(max(series)),
        "stdev": util.stdev([float(v) for v in series]),
    }
