"""
entity_fusion.storage.disk_cache — a tiny, dependency-free on-disk JSON cache
with TTL, for enricher responses that are worth surviving a process restart
(certificate transparency pages, WHOIS, DNS answers). Keys are hashed to safe
filenames; values must be JSON-serialisable.

This is intentionally *not* ``diskcache`` (a third-party lib): the repo is
stdlib-first, and the access pattern here (read-mostly, small values, best-effort
persistence) does not justify a dependency. All operations are best-effort — a
failed read/write logs and behaves like a miss rather than raising, so the cache
can never break the pipeline.
"""

from __future__ import annotations

import os
import json
import time
import hashlib
import logging
import tempfile
from typing import Any, Dict, Optional

logger = logging.getLogger("modbot.entity_fusion.diskcache")


class DiskCache:
    def __init__(self, directory: str, *, ttl: float = 86400.0):
        self.directory = directory
        self.ttl = float(ttl)
        try:
            os.makedirs(self.directory, exist_ok=True)
            self.enabled = True
        except Exception:
            logger.warning("DiskCache disabled: cannot create %s", directory,
                           exc_info=True)
            self.enabled = False

    def _path(self, key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return os.path.join(self.directory, f"{digest}.json")

    def get(self, key: str, default: Any = None) -> Any:
        if not self.enabled:
            return default
        path = self._path(key)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except FileNotFoundError:
            return default
        except Exception:
            logger.debug("DiskCache read failed for %s", key, exc_info=True)
            return default
        if self.ttl > 0 and (time.time() - payload.get("_ts", 0)) > self.ttl:
            self.delete(key)
            return default
        return payload.get("value", default)

    def set(self, key: str, value: Any) -> bool:
        if not self.enabled:
            return False
        path = self._path(key)
        payload = {"_ts": time.time(), "key": key, "value": value}
        try:
            # atomic write: temp file in the same dir, then rename
            fd, tmp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
            os.replace(tmp, path)
            return True
        except Exception:
            logger.debug("DiskCache write failed for %s", key, exc_info=True)
            return False

    def delete(self, key: str) -> None:
        try:
            os.remove(self._path(key))
        except FileNotFoundError:
            pass
        except Exception:
            logger.debug("DiskCache delete failed for %s", key, exc_info=True)

    def clear(self) -> int:
        if not self.enabled:
            return 0
        removed = 0
        try:
            for name in os.listdir(self.directory):
                if name.endswith(".json"):
                    try:
                        os.remove(os.path.join(self.directory, name))
                        removed += 1
                    except Exception:
                        pass
        except Exception:
            logger.debug("DiskCache clear failed", exc_info=True)
        return removed

    def stats(self) -> Dict[str, Any]:
        count = 0
        if self.enabled:
            try:
                count = sum(1 for n in os.listdir(self.directory)
                            if n.endswith(".json"))
            except Exception:
                pass
        return {"enabled": self.enabled, "directory": self.directory,
                "entries": count, "ttl": self.ttl}
