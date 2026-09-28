"""Tests for SQLite storage and caching."""

from __future__ import annotations

import os
import tempfile

import pytest

from behavioral_intelligence.models import Observation
from behavioral_intelligence.storage import (SQLiteStore, MemoryCache, DiskCache,
                                             LayeredCache)
from behavioral_intelligence.cache import CalculationCache, fingerprint
from behavioral_intelligence.tests.conftest import at, make_observations


@pytest.fixture
def db_path():
    p = tempfile.mktemp(suffix=".db")
    yield p
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(p + suffix)
        except OSError:
            pass


def test_observation_roundtrip(db_path):
    store = SQLiteStore(db_path)
    obs = make_observations(days=5, per_day=2)
    n = store.save_observations(obs)
    assert n == 10
    loaded = store.load_observations(entity_id="actor7")
    assert len(loaded) == 10
    assert loaded[0].platform == "mastodon"


def test_observation_upsert_idempotent(db_path):
    store = SQLiteStore(db_path)
    obs = make_observations(days=3, per_day=1)
    store.save_observations(obs)
    store.save_observations(obs)     # same observation_ids -> upsert, no dupes
    assert store.stats()["observations"] == 3


def test_time_filtered_load(db_path):
    store = SQLiteStore(db_path)
    store.save_observations([Observation(platform="x", account_id="a",
                                         timestamp=at(d), entity_id="e") for d in range(10)])
    subset = store.load_observations(entity_id="e", since=at(5))
    assert all(o.timestamp >= at(5) for o in subset)
    assert len(subset) == 5


def test_streaming_iter(db_path):
    store = SQLiteStore(db_path)
    store.save_observations([Observation(platform="x", account_id="a",
                                         timestamp=at(0) + i, entity_id="e",
                                         observation_id=f"o{i}") for i in range(50)])
    streamed = list(store.iter_observations(entity_id="e", batch_size=7))
    assert len(streamed) == 50


def test_prune_ttl(db_path):
    store = SQLiteStore(db_path)
    old = Observation(platform="x", account_id="a", timestamp=at(0),
                      observation_id="old")
    old.collected_at = 1000.0
    new = Observation(platform="x", account_id="a", timestamp=at(1),
                      observation_id="new")
    new.collected_at = 10 ** 12
    store.save_observations([old, new])
    removed = store.prune_observations(older_than=2000.0)
    assert removed == 1


def test_caches():
    for cache in (MemoryCache(), LayeredCache(None)):
        cache.set("ns", "k", {"v": 1}, ttl=100)
        assert cache.get("ns", "k") == {"v": 1}
        assert cache.get("ns", "missing") is None


def test_disk_cache(tmp_path):
    c = DiskCache(str(tmp_path))
    c.set("ns", "k", [1, 2, 3])
    assert c.get("ns", "k") == [1, 2, 3]


def test_calculation_cache_fingerprint_invalidation():
    obs1 = make_observations(days=3, per_day=1)
    obs2 = make_observations(days=4, per_day=1)
    fp1, fp2 = fingerprint(obs1), fingerprint(obs2)
    assert fp1 != fp2
    calls = {"n": 0}
    cache = CalculationCache()

    def compute():
        calls["n"] += 1
        return {"result": len(obs1)}

    cache.get_or_compute("agg", obs1, compute)
    cache.get_or_compute("agg", obs1, compute)   # cached -> no recompute
    assert calls["n"] == 1
    cache.get_or_compute("agg", obs2, compute)    # different data -> recompute
    assert calls["n"] == 2
