"""Tests for the temporal intelligence engine, including timezone/timestamp
precision handling."""

from __future__ import annotations

from datetime import datetime, timezone


from behavioral_intelligence.models import Observation, ObservationBatch, TimestampPrecision
from behavioral_intelligence.temporal import (TemporalEngine, burst_detection,
                                              inactivity_detection, change_point,
                                              hourly_analysis, daily_analysis)
from behavioral_intelligence.tests.conftest import at, make_observations


def test_activity_stats_basic():
    eng = TemporalEngine()
    batch = ObservationBatch(make_observations(days=30, per_day=2))
    stats = eng.activity_stats(batch.observations)
    assert stats.sample_size == 60
    assert stats.active_days == 30
    assert stats.posts_per_day > 1.5
    assert stats.intervals.count == 59


def test_peak_window_is_utc_and_no_chronotype_claim():
    eng = TemporalEngine()
    obs = make_observations(days=40, per_day=3, hour=21)
    batch = ObservationBatch(obs)
    result = eng.analyze(batch)
    assert result.peak_windows
    w = result.peak_windows[0]
    # 21:00 activity should place the peak window over the 21:00 hour
    assert w.start_hour <= 21 <= (w.end_hour or 24) or w.start_hour == 21
    # the assertion must be labelled OBSERVED and mention UTC, never "nocturnal"
    peak_assertions = [a for a in result.assertions if "peak_window" in a.tags]
    assert peak_assertions
    text = peak_assertions[0].statement.lower()
    assert "utc" in text
    assert "nocturnal" not in text


def test_burst_detection():
    obs = make_observations(days=10, per_day=1)
    # add a burst: 20 posts in 10 minutes on day 5
    for i in range(20):
        obs.append(Observation(platform="mastodon", account_id="alice",
                               timestamp=at(5, 20, 0) + i * 30, text="x"))
    bursts = burst_detection.detect_bursts(obs, window_minutes=15, min_count=5)
    assert bursts
    assert bursts[0].count >= 15
    assert bursts[0].relative_change > 1


def test_inactivity_detection_frames_as_lack_of_observation():
    obs = [Observation(platform="x", account_id="a", timestamp=at(d, 20))
           for d in range(10)]
    obs += [Observation(platform="x", account_id="a", timestamp=at(d, 20))
            for d in range(40, 50)]   # 30-day gap
    gaps = inactivity_detection.detect_inactivity(obs, min_gap_days=7)
    assert gaps
    assert gaps[0].duration_days > 20


def test_change_point_detects_rate_shift():
    # low rate then high rate
    obs = [Observation(platform="x", account_id="a", timestamp=at(d, 12))
           for d in range(30)]
    for d in range(30, 45):
        for i in range(8):
            obs.append(Observation(platform="x", account_id="a",
                                   timestamp=at(d, 12, i * 5)))
    labels, series = daily_analysis.dense_daily_series(obs)
    ts = [datetime.strptime(x, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
          for x in labels]
    cps = change_point.detect_change_points([float(v) for v in series], ts)
    assert cps
    assert any(c.direction == "increase" for c in cps)


def test_timestamp_precision_gates_hour_histogram():
    # day-precise observations must NOT populate the hour histogram
    obs = [Observation(platform="x", account_id="a", timestamp=at(d, 0),
                       timestamp_precision=TimestampPrecision.DAY) for d in range(20)]
    hist = hourly_analysis.hour_histogram(obs)
    assert hist.total == 0        # nothing placed in an hour it doesn't have


def test_timezone_offset_is_display_only():
    eng_utc = TemporalEngine(tz_offset_hours=0)
    eng_shift = TemporalEngine(tz_offset_hours=7)
    obs = make_observations(days=20, per_day=2, hour=20)
    h0 = eng_utc.heatmap(obs, "hour_weekday")
    h7 = eng_shift.heatmap(obs, "hour_weekday")
    # total activity identical; only the hour bucket shifts
    assert h0.total == h7.total
    assert h7.tz_offset_hours == 7


def test_cross_platform_correlation_is_labelled_correlated():
    obs = []
    for d in range(30):
        obs.append(Observation(platform="a", account_id="x", timestamp=at(d, 20), text="t"))
        obs.append(Observation(platform="b", account_id="x", timestamp=at(d, 21), text="t"))
    eng = TemporalEngine()
    result = eng.analyze(ObservationBatch(obs))
    assert result.correlations
    corr_assertions = [a for a in result.assertions if "cross_platform" in a.tags]
    assert corr_assertions
    assert corr_assertions[0].kind.value == "CORRELATED"
    # must carry the "does not prove same person" limitation
    lims = " ".join(x.text for x in corr_assertions[0].confidence.limitations)
    assert "same person" in lims.lower()
