"""
geo_osint.storage.cache_store — a small TTL disk cache for public-source responses.

Network map/geo sources (Nominatim, Wikidata, GeoNames, RDAP, cloud-region docs)
are polite-rate-limited and their answers change slowly, so caching them on disk
cuts request volume and respects provider usage policies (spec §17, §51). Keys are
hashed; values are JSON with a stored expiry. Entirely stdlib; failures degrade to
"cache miss" so a broken cache never breaks a run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger("modbot.geo_osint.cache")


class CacheStore:
    def __init__(self, directory: str = "", default_ttl_s: float = 86400.0) -> None:
        self._dir = directory or os.path.join(
            os.path.expanduser("~"), ".cache", "sombra_geo_osint")
        self._ttl = default_ttl_s
        self._enabled = True
        try:
            os.makedirs(self._dir, exist_ok=True)
        except OSError as exc:
            logger.info("cache disabled (cannot create %s): %s", self._dir, exc)
            self._enabled = False

    def _path(self, namespace: str, key: str) -> str:
        digest = hashlib.sha256(f"{namespace}:{key}".encode("utf-8")).hexdigest()
        return os.path.join(self._dir, f"{namespace}_{digest}.json")

    def get(self, namespace: str, key: str) -> Optional[Any]:
        if not self._enabled:
            return None
        path = self._path(namespace, key)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            return None
        if blob.get("expires_at", 0) < time.time():
            self._safe_remove(path)
            return None
        return blob.get("value")

    def set(self, namespace: str, key: str, value: Any,
            ttl_s: Optional[float] = None) -> None:
        if not self._enabled:
            return
        path = self._path(namespace, key)
        blob = {"stored_at": time.time(),
                "expires_at": time.time() + (ttl_s if ttl_s is not None else self._ttl),
                "value": value}
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(blob, fh, ensure_ascii=False)
            os.replace(tmp, path)
        except OSError as exc:
            logger.debug("cache write failed: %s", exc)

    def get_or_set(self, namespace: str, key: str, producer,
                   ttl_s: Optional[float] = None) -> Any:
        hit = self.get(namespace, key)
        if hit is not None:
            return hit
        value = producer()
        if value is not None:
            self.set(namespace, key, value, ttl_s)
        return value

    def clear(self, namespace: Optional[str] = None) -> int:
        if not self._enabled:
            return 0
        removed = 0
        try:
            for fn in os.listdir(self._dir):
                if namespace and not fn.startswith(f"{namespace}_"):
                    continue
                if fn.endswith(".json"):
                    self._safe_remove(os.path.join(self._dir, fn))
                    removed += 1
        except OSError:
            pass
        return removed

    @staticmethod
    def _safe_remove(path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass
