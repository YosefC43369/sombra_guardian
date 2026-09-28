"""
behavioral_intelligence.cache — the calculation cache (spec §36).

A thin, ergonomic layer over ``storage.cache_store.LayeredCache`` that memoises
expensive analytical results by a content-derived key. The key is built from the
observation-set fingerprint (a hash of the sorted observation ids + their content
hashes) plus the calculation name and parameters, so a result is reused only when
the *exact same inputs* recur — changing one observation invalidates the entry
(content-hash based invalidation, spec §36).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Dict, Optional, Sequence

from .storage.cache_store import LayeredCache, SQLiteCache
from .models.observation import Observation


def fingerprint(observations: Sequence[Observation]) -> str:
    """A stable fingerprint of an observation set: hash of the sorted
    (observation_id, content_hash, timestamp) triples. Two runs over the same
    data produce the same fingerprint; any change alters it."""
    h = hashlib.sha256()
    triples = sorted((o.observation_id, o.content_hash, f"{o.timestamp:.0f}")
                     for o in observations)
    for oid, ch, ts in triples:
        h.update(oid.encode())
        h.update(b"\x00")
        h.update(ch.encode())
        h.update(b"\x00")
        h.update(ts.encode())
        h.update(b"\x01")
    h.update(f"|n={len(triples)}".encode())
    return h.hexdigest()


class CalculationCache:
    def __init__(self, backend: Optional[LayeredCache] = None, *,
                 db_path: Optional[str] = None, default_ttl: float = 3600.0):
        if backend is not None:
            self.cache = backend
        elif db_path:
            self.cache = LayeredCache(SQLiteCache(db_path))
        else:
            self.cache = LayeredCache(None)   # memory-only
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _key(calc: str, obs_fp: str, params: Dict[str, Any]) -> str:
        param_str = json.dumps(params, sort_keys=True, ensure_ascii=False,
                               default=str)
        return f"{calc}|{obs_fp}|{param_str}"

    def get_or_compute(self, calc: str, observations: Sequence[Observation],
                       compute: Callable[[], Any], *, params: Optional[Dict] = None,
                       ttl: Optional[float] = None) -> Any:
        """Return the cached result for ``calc`` over ``observations`` (with
        ``params``), or compute, store and return it. ``compute`` must return a
        JSON-serialisable value (typically a model's ``to_dict()``)."""
        obs_fp = fingerprint(observations)
        key = self._key(calc, obs_fp, params or {})
        sentinel = object()
        cached = self.cache.get("calc", key, sentinel)
        if cached is not sentinel:
            self.hits += 1
            return cached
        self.misses += 1
        value = compute()
        self.cache.set("calc", key, value, ttl if ttl is not None else self.default_ttl)
        return value

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        return {"hits": self.hits, "misses": self.misses,
                "hit_rate": round(self.hits / total, 3) if total else 0.0}

    def clear(self) -> None:
        self.cache.clear()
