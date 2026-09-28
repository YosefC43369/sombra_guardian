"""
behavioral_intelligence.models.activity — typed results for temporal/activity
analysis.

These are the shapes the temporal engine returns. They are pure data (dataclass
+ ``to_dict``), computed over an explicit observation window so every figure is
reproducible and every rate carries the sample it was measured from.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Tuple


@dataclass
class IntervalStats:
    """Statistics of the gaps between consecutive timed observations (seconds)."""
    count: int = 0
    minimum: float = 0.0
    maximum: float = 0.0
    mean: float = 0.0
    median: float = 0.0
    stdev: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {k: (round(v, 3) if isinstance(v, float) else v)
                for k, v in asdict(self).items()}


@dataclass
class ActivityStats:
    """The headline temporal summary for one entity/window."""
    sample_size: int = 0
    period_start: float = 0.0
    period_end: float = 0.0
    period_days: float = 0.0
    posts_per_day: float = 0.0
    posts_per_active_day: float = 0.0
    active_days: int = 0
    inactive_days: int = 0
    coverage: float = 0.0            # active_days / period_days
    intervals: IntervalStats = field(default_factory=IntervalStats)
    first_seen: float = 0.0
    last_seen: float = 0.0
    per_platform: Dict[str, int] = field(default_factory=dict)
    per_content_type: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["intervals"] = self.intervals.to_dict()
        for k in ("posts_per_day", "posts_per_active_day", "coverage", "period_days"):
            d[k] = round(d[k], 3)
        return d


@dataclass
class Histogram:
    """A labelled 1-D count distribution (hour-of-day, weekday, month, …)."""
    dimension: str                     # e.g. "hour_utc"
    labels: List[str] = field(default_factory=list)
    counts: List[int] = field(default_factory=list)
    total: int = 0

    def peak(self) -> Tuple[str, int]:
        if not self.counts:
            return ("", 0)
        i = max(range(len(self.counts)), key=lambda j: self.counts[j])
        return (self.labels[i], self.counts[i])

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension, "labels": self.labels,
                "counts": self.counts, "total": self.total,
                "peak": {"label": self.peak()[0], "count": self.peak()[1]}}


@dataclass
class Heatmap:
    """A 2-D activity grid (e.g. hour-of-day × weekday). ``grid[r][c]`` is a
    count; ``row_labels``/``col_labels`` name the axes."""
    row_dimension: str
    col_dimension: str
    row_labels: List[str] = field(default_factory=list)
    col_labels: List[str] = field(default_factory=list)
    grid: List[List[int]] = field(default_factory=list)
    total: int = 0
    tz_offset_hours: float = 0.0       # display offset applied, if any

    def hottest(self) -> Tuple[str, str, int]:
        best = (-1, -1, -1)
        for r, row in enumerate(self.grid):
            for c, v in enumerate(row):
                if v > best[2]:
                    best = (r, c, v)
        if best[2] < 0:
            return ("", "", 0)
        return (self.row_labels[best[0]], self.col_labels[best[1]], best[2])

    def to_dict(self) -> Dict[str, Any]:
        rl, cl, v = self.hottest()
        return {
            "row_dimension": self.row_dimension,
            "col_dimension": self.col_dimension,
            "row_labels": self.row_labels,
            "col_labels": self.col_labels,
            "grid": self.grid,
            "total": self.total,
            "tz_offset_hours": self.tz_offset_hours,
            "hottest": {"row": rl, "col": cl, "count": v},
        }


@dataclass
class ActivityWindow:
    """A contiguous run of hours-of-day that concentrates activity, expressed in
    UTC. The temporal engine reports these instead of claiming a chronotype."""
    start_hour: int = 0
    end_hour: int = 0
    share: float = 0.0                 # fraction of activity inside the window
    tz_offset_hours: float = 0.0

    def label(self) -> str:
        return f"{self.start_hour:02d}:00–{self.end_hour:02d}:00 UTC"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["share"] = round(self.share, 3)
        d["label"] = self.label()
        return d


@dataclass
class Burst:
    """A window of unusually dense activity relative to baseline (spec §5)."""
    start: float = 0.0
    end: float = 0.0
    count: int = 0
    duration_seconds: float = 0.0
    rate_per_hour: float = 0.0
    baseline_per_hour: float = 0.0
    relative_change: float = 0.0       # rate / baseline
    absolute_change: float = 0.0       # rate - baseline
    platforms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("rate_per_hour", "baseline_per_hour", "relative_change",
                  "absolute_change", "duration_seconds"):
            d[k] = round(d[k], 3)
        return d


@dataclass
class InactivityGap:
    """A prolonged period with no observed public activity (spec §6). Explicitly
    *not* interpreted as physical absence — only lack of observation."""
    start: float = 0.0
    end: float = 0.0
    duration_seconds: float = 0.0
    prior_rate_per_day: float = 0.0
    following_rate_per_day: float = 0.0
    platforms_affected: List[str] = field(default_factory=list)

    @property
    def duration_days(self) -> float:
        return self.duration_seconds / 86400.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["duration_days"] = round(self.duration_days, 2)
        for k in ("prior_rate_per_day", "following_rate_per_day", "duration_seconds"):
            d[k] = round(d[k], 3)
        return d


@dataclass
class TemporalCorrelation:
    """Overlap of two platforms' hour-of-day activity (spec §4). Reports the
    overlap and correlation but explicitly does NOT assert same-person."""
    platform_a: str = ""
    platform_b: str = ""
    overlap_fraction: float = 0.0      # histogram intersection, 0..1
    pearson_r: float = 0.0
    sample_a: int = 0
    sample_b: int = 0
    period_days: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for k in ("overlap_fraction", "pearson_r", "period_days"):
            d[k] = round(d[k], 3)
        return d
