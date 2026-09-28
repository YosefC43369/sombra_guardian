"""
threat_actor_intelligence.storage.cache_store — unified cache facade.

Wraps the disk cache (``cache.DiskCache``) and the sqlite kv namespace behind one
small interface so ingestors and the orchestrator do not care where a cached
value lives: transient HTTP bodies and validators go to disk (cheap, evictable),
while durable small state (last-poll cursors, dedup markers) goes to sqlite.
"""

from __future__ import annotations

from typing import Any, Optional

from ..cache import DiskCache, Validators
from .sqlite_store import SQLiteStore


class CacheStore:
    def __init__(self, *, disk: Optional[DiskCache] = None,
                 store: Optional[SQLiteStore] = None,
                 cache_dir: str = ".tai_cache", default_ttl: float = 21600):
        self.disk = disk or DiskCache(cache_dir=cache_dir, default_ttl=default_ttl)
        self.store = store

    # transient (disk) --------------------------------------------------- #

    def get_http(self, url: str) -> Any:
        return self.disk.get("http", url)

    def set_http(self, url: str, body: Any, ttl: Optional[float] = None) -> None:
        self.disk.set("http", url, body, ttl=ttl)

    def get_validators(self, url: str) -> Validators:
        return self.disk.get_validators(url)

    def set_validators(self, url: str, v: Validators) -> None:
        self.disk.set_validators(url, v)

    # durable (sqlite) --------------------------------------------------- #

    def get_state(self, key: str, default: Any = None) -> Any:
        if self.store is None:
            return self.disk.get("state", key, default)
        return self.store.kv_get("cache_state", key, default)

    def set_state(self, key: str, value: Any, ttl: float = 0) -> None:
        if self.store is None:
            self.disk.set("state", key, value, ttl=ttl or None)
        else:
            self.store.kv_set("cache_state", key, value, ttl=ttl)

    def stats(self) -> dict:
        return {"disk": self.disk.stats(),
                "durable": "sqlite" if self.store else "disk"}


__all__ = ["CacheStore"]
