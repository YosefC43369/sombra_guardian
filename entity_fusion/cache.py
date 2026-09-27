"""
entity_fusion.cache — a unified, tiered cache facade over the memory, disk and
SQLite backends.

Reads check the fast tier first (memory), fall through to disk, then to SQLite;
a hit in a slower tier is promoted upward. Writes fan out to every configured
tier. This gives the recursive pipeline a single ``get``/``set`` surface while
letting the operator decide how durable each deployment needs to be (memory-only
for a one-shot run, +disk for restart survival, +SQLite for shared history).

Every tier is optional; with none configured the cache is a transparent no-op,
so code can always call through it.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .storage.memory_cache import MemoryCache
from .storage.disk_cache import DiskCache


class TieredCache:
    def __init__(self, *, memory: Optional[MemoryCache] = None,
                 disk: Optional[DiskCache] = None,
                 sqlite_store: Any = None, sqlite_namespace: str = "cache"):
        self.memory = memory
        self.disk = disk
        self.sqlite = sqlite_store
        self.ns = sqlite_namespace

    @classmethod
    def in_memory(cls, *, ttl: float = 300.0, max_size: int = 4096) -> "TieredCache":
        return cls(memory=MemoryCache(ttl=ttl, max_size=max_size))

    def get(self, key: str, default: Any = None) -> Any:
        sentinel = object()
        if self.memory is not None:
            v = self.memory.get(key, sentinel)
            if v is not sentinel:
                return v
        if self.disk is not None:
            v = self.disk.get(key, sentinel)
            if v is not sentinel:
                self._promote(key, v)
                return v
        if self.sqlite is not None:
            v = self.sqlite.cache_get(self.ns, key, sentinel)
            if v is not sentinel:
                self._promote(key, v)
                return v
        return default

    def _promote(self, key: str, value: Any) -> None:
        if self.memory is not None:
            self.memory.set(key, value)

    def set(self, key: str, value: Any, *, ttl: float = 0.0) -> None:
        if self.memory is not None:
            self.memory.set(key, value)
        if self.disk is not None:
            self.disk.set(key, value)
        if self.sqlite is not None:
            self.sqlite.cache_set(self.ns, key, value, ttl=ttl)

    def get_or_set(self, key: str, factory: Callable[[], Any], *,
                   ttl: float = 0.0) -> Any:
        sentinel = object()
        v = self.get(key, sentinel)
        if v is sentinel:
            v = factory()
            self.set(key, v, ttl=ttl)
        return v

    async def get_or_set_async(self, key: str, factory: Callable[[], Any], *,
                               ttl: float = 0.0) -> Any:
        sentinel = object()
        v = self.get(key, sentinel)
        if v is sentinel:
            v = await factory()
            self.set(key, v, ttl=ttl)
        return v

    def stats(self) -> dict:
        return {
            "memory": self.memory.stats() if self.memory else None,
            "disk": self.disk.stats() if self.disk else None,
            "sqlite": self.sqlite.stats() if self.sqlite else None,
        }
