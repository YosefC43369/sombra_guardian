"""Tests for the incremental pipeline and orchestrator."""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from behavioral_intelligence.models import Observation, ObservationBatch
from behavioral_intelligence.storage import ObservationStore
from behavioral_intelligence.pipeline import IncrementalPipeline, PipelineConfig
from behavioral_intelligence.orchestrator import BehavioralOrchestrator
from behavioral_intelligence.authorization import AuthorizationContext, Subject
from behavioral_intelligence.providers.base import BehaviorProvider
from behavioral_intelligence.tests.conftest import at, make_observations


@pytest.fixture
def store():
    p = tempfile.mktemp(suffix=".db")
    yield ObservationStore(db_path=p)
    for s in ("", "-wal", "-shm"):
        try:
            os.remove(p + s)
        except OSError:
            pass


def test_ingest_dedup(store):
    obs = [Observation(platform="x", account_id="a", timestamp=at(d), text="t",
                       entity_id="e", observation_id=f"o{d}") for d in range(10)]
    r = store.ingest(obs)
    assert r["ingested"] == 10
    r2 = store.ingest(obs)          # same dedupe keys -> all duplicates
    assert r2["ingested"] == 0
    assert r2["duplicates"] == 10


def test_pipeline_incremental_cursor(store):
    pipe = IncrementalPipeline(store=store)
    obs = make_observations(days=5, per_day=1)
    r = pipe.process("actor7", obs)
    assert r.ingested == 5
    cursor = store.cursor("actor7")
    assert cursor > 0
    # new batch with later collected_at
    more = make_observations(days=5, per_day=1)
    for i, o in enumerate(more):
        o.timestamp = at(100 + i)
        o.observation_id = f"new{i}"
    r2 = pipe.process("actor7", more)
    assert r2.ingested == 5


def test_pipeline_load_for_analysis(store):
    pipe = IncrementalPipeline(store=store,
                               pipeline_config=PipelineConfig(max_in_memory=1000))
    pipe.process("actor7", make_observations(days=10, per_day=2))
    batch = pipe.load_for_analysis("actor7")
    assert isinstance(batch, ObservationBatch)
    assert len(batch) == 20


class _StubProvider(BehaviorProvider):
    name = "stub"

    def __init__(self, obs, fail=False):
        super().__init__()
        self._obs = obs
        self._fail = fail

    async def collect(self, target):
        if self._fail:
            raise RuntimeError("boom")
        return self._obs


def test_orchestrator_isolates_provider_failure(store):
    good = _StubProvider(make_observations(days=3, per_day=1))
    bad = _StubProvider([], fail=True)
    orch = BehavioralOrchestrator(store=store, providers=[good, bad])
    ctx = AuthorizationContext(dev_unsafe_allow_all=True)
    profile = asyncio.get_event_loop().run_until_complete(
        orch.run("actor7", ctx, entity_id="actor7", subject=Subject.ACCOUNT))
    # good provider's data analysed despite bad provider failing
    assert profile.sample_size > 0
    statuses = {s["provider"]: s["status"] for s in profile.provider_status}
    assert statuses.get("stub") in ("ok", "error")   # both providers named 'stub'
    assert any(s["status"] == "error" for s in profile.provider_status)
    assert any(s["status"] == "ok" for s in profile.provider_status)
