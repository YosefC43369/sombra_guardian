"""
news_intelligence.cache — dependency-free disk + memory cache for the news engine.

Reuses the Threat Actor Intelligence Engine's proven ``DiskCache`` / ``Validators``
(same conditional-request-validator store, same atomic JSON-per-key layout) so the
two engines share one caching discipline. A self-contained fallback keeps the news
engine importable and its tests runnable if the CTI engine is absent.

Cached namespaces (spec CACHE ENGINE): rss, html, parsed_article, entity_extraction,
translation, topic_cluster — all keyed and TTL'd through the same interface.
"""

from __future__ import annotations

try:
    from threat_actor_intelligence.cache import DiskCache, Validators  # type: ignore
    _SHARED = True
except Exception:  # pragma: no cover
    _SHARED = False
    import hashlib
    import json
    import os
    import time
    from dataclasses import dataclass
    from typing import Any, Dict, Optional, Tuple

    def _safe_key(namespace: str, key: str) -> str:
        return hashlib.sha256(
            f"{namespace}|{key}".encode("utf-8")).hexdigest()[:40]

    @dataclass
    class Validators:
        etag: str = ""
        last_modified: str = ""
        content_hash: str = ""
        fetched_at: float = 0.0

        def to_dict(self):
            return {"etag": self.etag, "last_modified": self.last_modified,
                    "content_hash": self.content_hash, "fetched_at": self.fetched_at}

        @classmethod
        def from_dict(cls, d):
            return cls(etag=str(d.get("etag", "")),
                       last_modified=str(d.get("last_modified", "")),
                       content_hash=str(d.get("content_hash", "")),
                       fetched_at=float(d.get("fetched_at", 0.0) or 0.0))

    class DiskCache:
        def __init__(self, cache_dir: str = ".ni_cache", *, default_ttl: float = 21600,
                     max_memory_items: int = 512):
            self.cache_dir = cache_dir
            self.default_ttl = default_ttl
            self.max_memory_items = max_memory_items
            self._mem: Dict[str, Tuple[float, Any]] = {}
            os.makedirs(cache_dir, exist_ok=True)

        def _path(self, ns, key):
            return os.path.join(self.cache_dir, f"{_safe_key(ns, key)}.json")

        def get(self, namespace, key, default=None):
            mk = f"{namespace}|{key}"
            now = time.time()
            hit = self._mem.get(mk)
            if hit and hit[0] > now:
                return hit[1]
            path = self._path(namespace, key)
            if not os.path.exists(path):
                return default
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    rec = json.load(fh)
            except Exception:
                return default
            if rec.get("expires_at", 0) and rec["expires_at"] < now:
                self._evict_file(path)
                return default
            val = rec.get("value", default)
            self._mem_put(mk, val, rec.get("expires_at", 0) or (now + self.default_ttl))
            return val

        def set(self, namespace, key, value, ttl=None):
            now = time.time()
            ttl = self.default_ttl if ttl is None else ttl
            expires = (now + ttl) if ttl > 0 else 0
            rec = {"namespace": namespace, "key": key, "value": value,
                   "stored_at": now, "expires_at": expires}
            path = self._path(namespace, key)
            tmp = path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(rec, fh, ensure_ascii=False)
                os.replace(tmp, path)
            except Exception:
                return
            self._mem_put(f"{namespace}|{key}", value,
                          expires or (now + self.default_ttl))

        def _mem_put(self, mk, value, expires_at):
            if len(self._mem) >= self.max_memory_items:
                oldest = min(self._mem.items(), key=lambda kv: kv[1][0])[0]
                self._mem.pop(oldest, None)
            self._mem[mk] = (expires_at, value)

        def _evict_file(self, path):
            try:
                os.remove(path)
            except OSError:
                pass

        def get_validators(self, url):
            return Validators.from_dict(self.get("validators", url, {}) or {})

        def set_validators(self, url, v):
            self.set("validators", url, v.to_dict(), ttl=0)

        def clear(self):
            n = 0
            self._mem.clear()
            try:
                for fn in os.listdir(self.cache_dir):
                    if fn.endswith(".json"):
                        self._evict_file(os.path.join(self.cache_dir, fn))
                        n += 1
            except OSError:
                pass
            return n

        def stats(self):
            files = 0
            try:
                files = sum(1 for fn in os.listdir(self.cache_dir)
                            if fn.endswith(".json"))
            except OSError:
                pass
            return {"cache_dir": self.cache_dir, "files": files,
                    "memory_items": len(self._mem), "default_ttl": self.default_ttl}


__all__ = ["DiskCache", "Validators"]
