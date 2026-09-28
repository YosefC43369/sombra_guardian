"""Tests for baseline, anomaly scoring, outliers, drift, change detection."""

from __future__ import annotations

from behavioral_intelligence.models import Observation
from behavioral_intelligence.anomaly import (build_baseline, AnomalyEngine,
                                             measure_drift,
                                             detect_changes)
from behavioral_intelligence.anomaly.outlier import zscore_outliers, mad_outliers
from behavioral_intelligence.tests.conftest import at, make_observations


def test_baseline_construction():
    obs = make_observations(days=30, per_day=3)
    b = build_baseline(obs, window_days=30, entity_id="e1")
    assert b.sample_size == 90
    assert b.posts_per_day > 2
    assert "en" in b.language_distribution


def test_anomaly_engine_flags_rate_and_language_shift():
    obs = []
    # baseline: 2/day english for 30 days
    for d in range(30):
        for _ in range(2):
            obs.append(Observation(platform="x", account_id="a", timestamp=at(d, 20),
                                   text="english osint content", language="en"))
    # observed window: 12/day thai, days 31-38
    for d in range(31, 39):
        for i in range(12):
            obs.append(Observation(platform="x", account_id="a",
                                   timestamp=at(d, 3, i), text="สวัสดี ทดสอบ",
                                   language="th"))
    eng = AnomalyEngine(observed_window_days=8, baseline_window_days=30)
    score, anomalies, assertions = eng.analyze(obs, entity_id="a")
    assert score.score > 40                     # significant deviation
    assert score.band != "normal relative to baseline"
    kinds = {a.kind for a in anomalies}
    assert "posting_rate_shift" in kinds
    assert "language_mix_shift" in kinds
    # the score is explicitly NOT a threat score
    note = score.to_dict()["note"].lower()
    assert "not a measure" in note or "not a" in note
    # every deviation exposes its contribution
    assert all(hasattr(d, "contribution") for d in score.deviations)


def test_anomaly_score_deterministic():
    obs = make_observations(days=40, per_day=3)
    e1 = AnomalyEngine().analyze(obs, entity_id="a")[0]
    e2 = AnomalyEngine().analyze(obs, entity_id="a")[0]
    assert abs(e1.score - e2.score) < 1e-9


def test_outlier_methods():
    # spread around ~10 with one spike at index 5; MAD needs a non-zero median
    # absolute deviation, so the baseline values must not be all identical.
    series = [10, 12, 9, 11, 13, 60, 10, 8, 11]
    assert any(o.index == 5 for o in zscore_outliers(series, threshold=2))
    assert any(o.index == 5 for o in mad_outliers(series, threshold=3))


def test_drift_between_windows():
    early = [Observation(platform="x", account_id="a", timestamp=at(d),
                         text="english", language="en") for d in range(20)]
    late = [Observation(platform="x", account_id="a", timestamp=at(30 + d),
                        text="ไทย", language="th") for d in range(20)]
    drift = measure_drift(early, late, feature="language")
    assert drift.distance > 0.5             # near-total language change


def test_change_detection_language_event():
    obs = [Observation(platform="x", account_id="a", timestamp=at(d, 20),
                       text="english text here", language="en") for d in range(15)]
    obs += [Observation(platform="x", account_id="a", timestamp=at(15 + d, 20),
                        text="ภาษาไทย", language="th") for d in range(15)]
    changes = detect_changes(obs)
    assert any(c.kind == "language_change" for c in changes)
