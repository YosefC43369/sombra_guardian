"""
entity_fusion.storage.memory_cache — an in-process TTL + LRU cache.

Used to memoize expensive, idempotent lookups within a single run (a normalized
value, a similarity score, an enricher response) so the recursive pipeline does
not recompute or re-fetch the same thing. Thread-safe via a simple lock; pure
stdlib (``collections.OrderedDict`` + ``threading`` + ``time``).
"""

from __future__ import annotations

import time
import threading
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional, Tuple


class MemoryCache:
    """Bounded TTL cache with LRU eviction.

    ``ttl`` seconds (0 = no expiry). ``max_size`` entries before the least
    recently used is evicted. ``get``/``set`` are O(1) amortized."""

    def __init__(self, *, ttl: float = 300.0, max_size: int = 4096):
        self.ttl = float(ttl)
        self.max_size = int(max_size)
        self._data: "OrderedDict[str, Tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def _expired(self, stamped_at: float) -> bool:
        return self.ttl > 0 and (time.monotonic() - stamped_at) > self.ttl

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                self.misses += 1
                return default
            stamped_at, value = item
            if self._expired(stamped_at):
                del self._data[key]
                self.misses += 1
                return default
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = (time.monotonic(), value)
            while len(self._data) > self.max_size:
                self._data.popitem(last=False)   # evict LRU

    def get_or_set(self, key: str, factory: Callable[[], Any]) -> Any:
        sentinel = object()
        value = self.get(key, sentinel)
        if value is sentinel:
            value = factory()
            self.set(key, value)
        return value

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        return {"size": len(self), "hits": self.hits, "misses": self.misses,
                "hit_rate": round(self.hits / total, 3) if total else 0.0,
                "ttl": self.ttl, "max_size": self.max_size}
