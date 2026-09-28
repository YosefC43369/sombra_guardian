"""End-to-end tests for the BehavioralEngine service surface."""

from __future__ import annotations

import pytest

from behavioral_intelligence import BehavioralEngine, ObservationBatch
from behavioral_intelligence.authorization import AuthorizationContext, Subject
from behavioral_intelligence.models.behavior import BehaviorProfile
from behavioral_intelligence.tests.conftest import make_observations


@pytest.fixture
def engine():
    return BehavioralEngine()


@pytest.fixture
def batch():
    return ObservationBatch(make_observations(), entity_id="actor7", label="@alice")


def test_analyze_entity_returns_profile(engine, batch, dev_ctx):
    p = engine.analyze_entity(batch, dev_ctx)
    assert isinstance(p, BehaviorProfile)
    assert p.sample_size == len(batch)
    assert p.activity is not None
    assert p.anomaly_score is not None
    assert p.assertions
    assert p.limitations       # standing limitations always present


def test_analyze_entity_denied_without_scope(engine, batch):
    with pytest.raises(PermissionError):
        engine.analyze_entity(batch, AuthorizationContext(), subject=Subject.ACCOUNT)


def test_all_typed_api_methods(engine, batch, dev_ctx):
    assert engine.build_baseline(batch, dev_ctx).sample_size > 0
    score, anomalies, assertions = engine.detect_anomalies(batch, dev_ctx)
    assert score is not None
    assert engine.build_timeline(batch, dev_ctx) is not None
    langs = engine.analyze_languages(batch, dev_ctx)
    assert "distribution" in langs and "not inferred" in langs["limitation"].lower()
    topics = engine.analyze_topics(batch, dev_ctx)
    assert "keywords" in topics
    inter = engine.analyze_interactions(batch, dev_ctx)
    assert "network" in inter
    comp = engine.compare_periods(batch, dev_ctx, window_days=15)
    assert comp.current_period and comp.previous_period is not None


def test_generate_report(engine, batch, dev_ctx):
    md = engine.generate_report(batch, dev_ctx, fmt="markdown")
    assert "Behavioral Intelligence Report" in md
    js = engine.generate_report(batch, dev_ctx, fmt="json")
    assert js.strip().startswith("{")


def test_period_comparison_deltas(engine, dev_ctx):
    # 30 days low then 30 days high
    from behavioral_intelligence.models import Observation
    from behavioral_intelligence.tests.conftest import at
    obs = [Observation(platform="x", account_id="a", timestamp=at(d, 20),
                       text="t", entity_id="e") for d in range(30)]
    for d in range(30, 60):
        for i in range(5):
            obs.append(Observation(platform="x", account_id="a", timestamp=at(d, 20, i),
                                   text="t", entity_id="e"))
    comp = engine.compare_periods(ObservationBatch(obs, entity_id="e"), dev_ctx,
                                  window_days=30)
    assert comp.deltas["count"] > 0        # more activity in the recent window
