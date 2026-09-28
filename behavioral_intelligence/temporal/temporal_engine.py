"""
behavioral_intelligence.temporal.temporal_engine — the temporal intelligence
engine (spec §2–7).

Composes the granular analyses (hourly/daily/weekly/monthly, bursts, inactivity,
change points, seasonality) into one ``TemporalResult`` and, crucially, turns the
raw statistics into properly-labelled ``Assertion`` objects. The engine reports
*when activity was observed*; it never asserts a chronotype, a location or a
lifestyle. Peak windows are stated in UTC with the share they hold, and any
timezone shift is flagged as a display choice, not evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..models.observation import Observation, ObservationBatch
from ..models.activity import (ActivityStats, IntervalStats, Histogram, Heatmap,
                               ActivityWindow, Burst, InactivityGap,
                               TemporalCorrelation)
from ..models.confidence import Assertion, AssertionKind, make_confidence
from .. import util
from . import (hourly_analysis, daily_analysis, weekly_analysis, monthly_analysis,
               burst_detection, inactivity_detection, change_point, seasonality)


@dataclass
class TemporalResult:
    stats: ActivityStats = field(default_factory=ActivityStats)
    hour_histogram: Optional[Histogram] = None
    weekday_histogram: Optional[Histogram] = None
    monthly_series_labels: List[str] = field(default_factory=list)
    monthly_series_values: List[int] = field(default_factory=list)
    heatmap: Optional[Heatmap] = None
    peak_windows: List[ActivityWindow] = field(default_factory=list)
    bursts: List[Burst] = field(default_factory=list)
    inactivity: List[InactivityGap] = field(default_factory=list)
    change_points: List = field(default_factory=list)
    seasonality: Optional[seasonality.SeasonalityResult] = None
    correlations: List[TemporalCorrelation] = field(default_factory=list)
    assertions: List[Assertion] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "stats": self.stats.to_dict(),
            "hour_histogram": self.hour_histogram.to_dict() if self.hour_histogram else None,
            "weekday_histogram": self.weekday_histogram.to_dict() if self.weekday_histogram else None,
            "monthly_series": {"labels": self.monthly_series_labels,
                               "values": self.monthly_series_values},
            "heatmap": self.heatmap.to_dict() if self.heatmap else None,
            "peak_windows": [w.to_dict() for w in self.peak_windows],
            "bursts": [b.to_dict() for b in self.bursts],
            "inactivity": [g.to_dict() for g in self.inactivity],
            "change_points": [c.to_dict() for c in self.change_points],
            "seasonality": self.seasonality.to_dict() if self.seasonality else None,
            "correlations": [c.to_dict() for c in self.correlations],
            "assertions": [a.to_dict() for a in self.assertions],
        }


class TemporalEngine:
    def __init__(self, *, tz_offset_hours: float = 0.0, burst_window_minutes: int = 15,
                 inactivity_min_days: float = 7.0, changepoint_z: float = 3.0,
                 source_count: int = 1):
        self.tz_offset_hours = tz_offset_hours
        self.burst_window_minutes = burst_window_minutes
        self.inactivity_min_days = inactivity_min_days
        self.changepoint_z = changepoint_z
        self.source_count = source_count

    # -- headline stats ---------------------------------------------------- #

    def activity_stats(self, observations: Sequence[Observation]) -> ActivityStats:
        timed = sorted((o for o in observations if o.has_time),
                       key=lambda o: o.timestamp)
        stats = ActivityStats(sample_size=len(observations))
        if not timed:
            return stats
        stats.first_seen = timed[0].timestamp
        stats.last_seen = timed[-1].timestamp
        stats.period_start = timed[0].timestamp
        stats.period_end = timed[-1].timestamp
        stats.period_days = max((timed[-1].timestamp - timed[0].timestamp)
                                / util.DAY_SECONDS, 0.0)

        gaps = [timed[i + 1].timestamp - timed[i].timestamp
                for i in range(len(timed) - 1)]
        if gaps:
            stats.intervals = IntervalStats(
                count=len(gaps), minimum=min(gaps), maximum=max(gaps),
                mean=util.mean(gaps), median=util.median(gaps),
                stdev=util.stdev(gaps))

        active, inactive = daily_analysis.active_inactive_days(observations)
        stats.active_days = active
        stats.inactive_days = inactive
        total_days = max(active + inactive, 1)
        stats.coverage = util.safe_div(active, total_days)
        stats.posts_per_day = util.safe_div(len(timed), max(stats.period_days, 1.0))
        stats.posts_per_active_day = util.safe_div(len(timed), max(active, 1))

        for o in observations:
            if o.platform:
                stats.per_platform[o.platform] = stats.per_platform.get(o.platform, 0) + 1
            ct = o.content_type.value
            stats.per_content_type[ct] = stats.per_content_type.get(ct, 0) + 1
        return stats

    # -- heatmaps (spec §3) ------------------------------------------------ #

    def heatmap(self, observations: Sequence[Observation],
                kind: str = "hour_weekday") -> Heatmap:
        """Build a 2-D activity heatmap. ``kind`` selects the axes:
        hour_weekday | hour_date | day_month | platform_hour | platform_day."""
        offset = self.tz_offset_hours
        if kind == "hour_weekday":
            rows = list(util.WEEKDAY_LABELS)
            cols = [f"{h:02d}" for h in range(24)]
            grid = [[0] * 24 for _ in range(7)]
            for o in observations:
                if o.has_time and o.timestamp_precision.supports_hour:
                    grid[o.weekday_utc][o.local_hour(offset)] += 1
            return Heatmap("weekday", "hour_utc", rows, cols, grid,
                           sum(sum(r) for r in grid), offset)
        if kind == "platform_hour":
            plats = sorted({o.platform for o in observations if o.platform})
            cols = [f"{h:02d}" for h in range(24)]
            idx = {p: i for i, p in enumerate(plats)}
            grid = [[0] * 24 for _ in plats]
            for o in observations:
                if o.platform and o.has_time and o.timestamp_precision.supports_hour:
                    grid[idx[o.platform]][o.local_hour(offset)] += 1
            return Heatmap("platform", "hour_utc", plats, cols, grid,
                           sum(sum(r) for r in grid), offset)
        if kind == "platform_day":
            plats = sorted({o.platform for o in observations if o.platform})
            cols = list(util.WEEKDAY_LABELS)
            idx = {p: i for i, p in enumerate(plats)}
            grid = [[0] * 7 for _ in plats]
            for o in observations:
                if o.platform and o.has_time and o.timestamp_precision.supports_day:
                    grid[idx[o.platform]][o.weekday_utc] += 1
            return Heatmap("platform", "weekday", plats, cols, grid,
                           sum(sum(r) for r in grid), offset)
        if kind == "day_month":
            months = monthly_analysis.monthly_series(observations)[0]
            cols = list(util.WEEKDAY_LABELS)
            idx = {mth: i for i, mth in enumerate(months)}
            grid = [[0] * 7 for _ in months]
            for o in observations:
                if o.has_time and o.month_utc in idx:
                    grid[idx[o.month_utc]][o.weekday_utc] += 1
            return Heatmap("month", "weekday", months, cols, grid,
                           sum(sum(r) for r in grid), offset)
        # default hour_date (recent 60 dates to stay readable)
        labels, _ = daily_analysis.dense_daily_series(observations)
        labels = labels[-60:]
        idx = {d: i for i, d in enumerate(labels)}
        grid = [[0] * 24 for _ in labels]
        for o in observations:
            if o.has_time and o.timestamp_precision.supports_hour and o.date_utc in idx:
                grid[idx[o.date_utc]][o.local_hour(offset)] += 1
        return Heatmap("date", "hour_utc", labels, [f"{h:02d}" for h in range(24)],
                       grid, sum(sum(r) for r in grid), offset)

    # -- cross-platform correlation (spec §4) ------------------------------ #

    def cross_platform_correlation(self, observations: Sequence[Observation]
                                   ) -> List[TemporalCorrelation]:
        by_platform: Dict[str, List[Observation]] = {}
        for o in observations:
            if o.platform and o.has_time and o.timestamp_precision.supports_hour:
                by_platform.setdefault(o.platform, []).append(o)
        plats = sorted(by_platform)
        out: List[TemporalCorrelation] = []
        for i in range(len(plats)):
            for j in range(i + 1, len(plats)):
                a, b = plats[i], plats[j]
                ha = hourly_analysis.hour_histogram(by_platform[a], self.tz_offset_hours)
                hb = hourly_analysis.hour_histogram(by_platform[b], self.tz_offset_hours)
                lo = min(min(o.timestamp for o in by_platform[a]),
                         min(o.timestamp for o in by_platform[b]))
                hi = max(max(o.timestamp for o in by_platform[a]),
                         max(o.timestamp for o in by_platform[b]))
                out.append(TemporalCorrelation(
                    platform_a=a, platform_b=b,
                    overlap_fraction=util.histogram_intersection(ha.counts, hb.counts),
                    pearson_r=util.pearson([float(x) for x in ha.counts],
                                           [float(x) for x in hb.counts]),
                    sample_a=ha.total, sample_b=hb.total,
                    period_days=(hi - lo) / util.DAY_SECONDS))
        out.sort(key=lambda c: c.overlap_fraction, reverse=True)
        return out

    # -- full analysis ----------------------------------------------------- #

    def analyze(self, batch: ObservationBatch) -> TemporalResult:
        obs = batch.observations
        result = TemporalResult()
        result.stats = self.activity_stats(obs)
        result.hour_histogram = hourly_analysis.hour_histogram(obs, self.tz_offset_hours)
        result.weekday_histogram = weekly_analysis.weekday_histogram(obs, self.tz_offset_hours)
        result.monthly_series_labels, result.monthly_series_values = \
            monthly_analysis.monthly_series(obs)
        result.heatmap = self.heatmap(obs, "hour_weekday")
        result.peak_windows = hourly_analysis.peak_windows(
            result.hour_histogram, tz_offset_hours=self.tz_offset_hours)
        result.bursts = burst_detection.detect_bursts(
            obs, window_minutes=self.burst_window_minutes)
        result.inactivity = inactivity_detection.detect_inactivity(
            obs, min_gap_days=self.inactivity_min_days)

        labels, series = daily_analysis.dense_daily_series(obs)
        if series:
            from datetime import datetime, timezone
            ts = [datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
                  for d in labels]
            result.change_points = change_point.detect_change_points(
                [float(v) for v in series], ts, zscore_threshold=self.changepoint_z)
            result.seasonality = seasonality.detect_seasonality([float(v) for v in series])

        result.correlations = self.cross_platform_correlation(obs)
        result.assertions = self._assertions(result, batch)
        return result

    # -- assertion synthesis ---------------------------------------------- #

    def _assertions(self, r: TemporalResult, batch: ObservationBatch) -> List[Assertion]:
        out: List[Assertion] = []
        n = r.stats.sample_size
        days = r.stats.period_days
        span = (r.stats.period_start, r.stats.period_end)

        if n == 0:
            return out

        # posting rate (OBSERVED)
        out.append(Assertion(
            statement=(f"{n} public observations over {days:.0f} days "
                       f"(~{r.stats.posts_per_day:.2f}/day; "
                       f"{r.stats.active_days} active days)."),
            kind=AssertionKind.OBSERVED,
            confidence=make_confidence(sample_size=n, period_days=days,
                                       source_count=self.source_count,
                                       supporting=["daily activity series"]),
            observation_period=span, tags=["activity_rate"]))

        # peak window (OBSERVED, explicitly UTC, no chronotype claim)
        if r.peak_windows:
            w = r.peak_windows[0]
            hist_total = r.hour_histogram.total if r.hour_histogram else n
            conf = make_confidence(sample_size=hist_total, period_days=days,
                                   source_count=self.source_count,
                                   supporting=["hour-of-day histogram"])
            if self.tz_offset_hours:
                conf.add_limitation(
                    f"Hours shown after a display shift of {self.tz_offset_hours:+.0f}h; "
                    f"timezone is not asserted as identity evidence.", "caution")
            out.append(Assertion(
                statement=(f"Public activity was concentrated in "
                           f"{w.label()} during the observed period "
                           f"({w.share*100:.0f}% of timed activity)."),
                kind=AssertionKind.OBSERVED, confidence=conf,
                observation_period=span, tags=["peak_window"],
                detail={"window": w.to_dict()}))

        # bursts
        if r.bursts:
            b = r.bursts[0]
            out.append(Assertion(
                statement=(f"A posting burst of {b.count} items in "
                           f"{b.duration_seconds/60:.0f} min "
                           f"({b.relative_change:.1f}× baseline) was observed."),
                kind=AssertionKind.OBSERVED,
                confidence=make_confidence(sample_size=b.count, period_days=days,
                                           source_count=self.source_count,
                                           supporting=["sliding-window rate"]),
                observation_period=(b.start, b.end), tags=["burst"],
                detail=b.to_dict()))

        # change points
        if r.change_points:
            cp = max(r.change_points, key=lambda c: c.magnitude)
            out.append(Assertion(
                statement=(f"A change in posting frequency ({cp.direction}) was "
                           f"detected (method={cp.method}, {cp.magnitude:.1f}σ)."),
                kind=AssertionKind.OBSERVED,
                confidence=make_confidence(sample_size=n, period_days=days,
                                           source_count=self.source_count,
                                           supporting=[cp.method, "activity series"]),
                observation_period=span, tags=["change_point"],
                detail=cp.to_dict()))

        # inactivity (framed as lack of observation)
        if r.inactivity:
            g = r.inactivity[0]
            out.append(Assertion(
                statement=(f"A {g.duration_days:.0f}-day period with no observed "
                           f"public activity was recorded (lack of observation, "
                           f"not evidence of absence)."),
                kind=AssertionKind.OBSERVED,
                confidence=make_confidence(sample_size=n, period_days=days,
                                           source_count=self.source_count,
                                           supporting=["inter-event gaps"]),
                observation_period=(g.start, g.end), tags=["inactivity"],
                detail=g.to_dict()))

        # cross-platform correlation is CORRELATED, never same-person
        for c in r.correlations[:1]:
            conf = make_confidence(sample_size=min(c.sample_a, c.sample_b),
                                   period_days=c.period_days,
                                   source_count=self.source_count,
                                   supporting=["hour-of-day histogram intersection"])
            conf.add_limitation(
                "Synchronised activity does not prove the accounts belong to the "
                "same person; it is a temporal coincidence only.", "critical")
            out.append(Assertion(
                statement=(f"{c.platform_a} and {c.platform_b} show "
                           f"{c.overlap_fraction*100:.0f}% hour-of-day overlap "
                           f"(r={c.pearson_r:.2f})."),
                kind=AssertionKind.CORRELATED, confidence=conf,
                observation_period=span, tags=["cross_platform"],
                detail=c.to_dict()))

        # seasonality
        if r.seasonality and r.seasonality.detected:
            out.append(Assertion(
                statement=(f"Activity recurs on an ~{r.seasonality.dominant_lag}-day "
                           f"cycle (autocorrelation "
                           f"{r.seasonality.strength:.2f})."),
                kind=AssertionKind.OBSERVED,
                confidence=make_confidence(sample_size=n, period_days=days,
                                           source_count=self.source_count,
                                           supporting=["series autocorrelation"]),
                observation_period=span, tags=["seasonality"]))
        return out
