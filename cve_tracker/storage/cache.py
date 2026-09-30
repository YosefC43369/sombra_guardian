"""
cve_tracker.storage.cache — a tiny async-safe TTL cache.

Used for things whose freshness has a short shelf-life: recent search results,
source metadata, KEV lookups within a round, and (via the AI cache) identical
summary requests. Deliberately in-process and bounded — persistent caching of
CVE records is the repository's job; this is only for hot, cheap-to-recompute
values (rule §26: TTL where appropriate, never cache indefinitely when
freshness matters).
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple


class TTLCache:
    """Thread-safe TTL cache with a max size (LRU-ish eviction by insertion
    order when full)."""

    def __init__(self, *, ttl: float = 900.0, max_size: int = 2048):
        self.ttl = float(ttl)
        self.max_size = int(max_size)
        self._store: Dict[Any, Tuple[float, Any]] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: Any, default=None):
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return default
            expires, value = entry
            if expires < now:
                self._store.pop(key, None)
                self._misses += 1
                return default
            self._hits += 1
            return value

    def set(self, key: Any, value: Any, *, ttl: Optional[float] = None) -> None:
        expires = time.monotonic() + (ttl if ttl is not None else self.ttl)
        with self._lock:
            if len(self._store) >= self.max_size and key not in self._store:
                # Evict the oldest-inserted entry.
                try:
                    oldest = next(iter(self._store))
                    self._store.pop(oldest, None)
                except StopIteration:
                    pass
            self._store[key] = (expires, value)

    def get_or_set(self, key: Any, factory: Callable[[], Any],
                   *, ttl: Optional[float] = None) -> Any:
        found = self.get(key, _SENTINEL)
        if found is not _SENTINEL:
            return found
        value = factory()
        self.set(key, value, ttl=ttl)
        return value

    def invalidate(self, key: Any) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def purge_expired(self) -> int:
        now = time.monotonic()
        removed = 0
        with self._lock:
            for k in [k for k, (exp, _) in self._store.items() if exp < now]:
                self._store.pop(k, None)
                removed += 1
        return removed

    @property
    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "size": len(self._store),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 3) if total else 0.0,
        }


_SENTINEL = object()
