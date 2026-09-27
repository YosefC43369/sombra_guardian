"""Tests for entity_fusion.storage — SQLite store round-trips, aliases,
relationships, history, and the memory/disk/tiered caches. Uses tmp_path so no
state leaks between runs."""

import time
import pytest

from entity_fusion.entity import (Entity, EntityType, SourceRef, Evidence,
                                   Relationship, RelationType)
from entity_fusion.storage import SQLiteStore, MemoryCache, DiskCache
from entity_fusion.cache import TieredCache


def _entity():
    e = Entity(type=EntityType.USERNAME, value="johndoe")
    e.normalized = "johndoe"
    e.add_alias("john.doe")
    e.add_source(SourceRef(provider="github", url="https://github.com/johndoe"))
    e.add_evidence(Evidence(kind="github_profile", value="johndoe", weight=0.3))
    e.add_relationship(Relationship(target_id="other-id", type=RelationType.OWNS))
    return e


class TestSQLiteStore:
    def test_roundtrip(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        e = _entity()
        store.save_entity(e)
        got = store.get_entity(e.id)
        assert got is not None
        assert got.value == "johndoe"
        assert "john.doe" in got.aliases

    def test_find_by_type_and_normalized(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        store.save_entity(_entity())
        found = store.find_entities(entity_type="username", normalized="johndoe")
        assert len(found) == 1

    def test_find_by_alias(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        store.save_entity(_entity())
        found = store.find_by_alias("john.doe")
        assert len(found) == 1

    def test_relationships_persisted(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        e = _entity()
        store.save_entity(e)
        rels = store.relationships_for(e.id)
        assert any(r["dst_id"] == "other-id" for r in rels)

    def test_history_recorded_on_change(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        e = _entity()
        store.save_entity(e)
        e.value = "john_doe_renamed"
        e.confidence = 88.0
        store.save_entity(e)
        hist = store.history_for(e.id)
        fields = {h["field"] for h in hist}
        assert "value" in fields or "confidence" in fields

    def test_cache_set_get_ttl(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        store.cache_set("ns", "k", {"a": 1}, ttl=100)
        assert store.cache_get("ns", "k") == {"a": 1}

    def test_cache_expiry(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        store.cache_set("ns", "k", "v", ttl=0.0001)
        time.sleep(0.01)
        assert store.cache_get("ns", "k", "default") == "default"

    def test_stats(self, tmp_path):
        store = SQLiteStore(str(tmp_path / "ef.db"))
        store.save_entity(_entity())
        s = store.stats()
        assert s["entities"] == 1


class TestMemoryCache:
    def test_set_get(self):
        c = MemoryCache(ttl=100)
        c.set("k", 42)
        assert c.get("k") == 42
        assert c.hits == 1

    def test_expiry(self):
        c = MemoryCache(ttl=0.0001)
        c.set("k", 1)
        time.sleep(0.01)
        assert c.get("k", "d") == "d"

    def test_lru_eviction(self):
        c = MemoryCache(ttl=0, max_size=2)
        c.set("a", 1); c.set("b", 2); c.set("c", 3)
        assert len(c) == 2
        assert c.get("a", None) is None   # 'a' evicted

    def test_get_or_set(self):
        c = MemoryCache()
        calls = []
        def factory():
            calls.append(1)
            return 7
        assert c.get_or_set("k", factory) == 7
        assert c.get_or_set("k", factory) == 7
        assert len(calls) == 1


class TestDiskCache:
    def test_set_get(self, tmp_path):
        c = DiskCache(str(tmp_path / "dc"))
        c.set("k", {"x": 1})
        assert c.get("k") == {"x": 1}

    def test_survives_new_instance(self, tmp_path):
        d = str(tmp_path / "dc")
        DiskCache(d).set("k", "v")
        assert DiskCache(d).get("k") == "v"

    def test_expiry(self, tmp_path):
        c = DiskCache(str(tmp_path / "dc"), ttl=0.0001)
        c.set("k", "v")
        time.sleep(0.01)
        assert c.get("k", "d") == "d"

    def test_delete_and_clear_and_stats(self, tmp_path):
        c = DiskCache(str(tmp_path / "dc"))
        c.set("a", 1)
        c.set("b", 2)
        assert c.stats()["entries"] == 2
        c.delete("a")
        assert c.get("a", "gone") == "gone"
        removed = c.clear()
        assert removed >= 1
        assert c.stats()["entries"] == 0

    def test_disabled_when_dir_uncreatable(self, tmp_path):
        # a path under a file cannot be a directory → cache disables gracefully
        f = tmp_path / "afile"
        f.write_text("x")
        c = DiskCache(str(f / "sub"))
        assert c.enabled is False
        assert c.set("k", "v") is False
        assert c.get("k", "d") == "d"


class TestTieredCache:
    def test_memory_then_disk_promotion(self, tmp_path):
        disk = DiskCache(str(tmp_path / "dc"))
        mem = MemoryCache()
        tc = TieredCache(memory=mem, disk=disk)
        disk.set("k", "fromdisk")
        assert tc.get("k") == "fromdisk"
        assert mem.get("k") == "fromdisk"   # promoted upward

    def test_set_fans_out(self, tmp_path):
        disk = DiskCache(str(tmp_path / "dc"))
        tc = TieredCache(memory=MemoryCache(), disk=disk)
        tc.set("k", "v")
        assert disk.get("k") == "v"
