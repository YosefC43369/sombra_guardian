"""
behavioral_intelligence.storage.cache_store — layered cache backends (spec §36).

Three interchangeable backends behind one ``CacheBackend`` protocol:
  * MemoryCache — process-local dict with TTL and an LRU cap.
  * DiskCache — JSON files under a directory, keyed by a hashed key.
  * SQLiteCache — a (namespace, key) table with TTL, in the behavioural DB.

``LayeredCache`` chains memory over a persistent backend so hot keys are served
from RAM while surviving process restarts. All reads/writes are total (never
raise on a missing/corrupt entry — they miss instead), because a cache fault
must degrade to recomputation, never crash an investigation.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import sqlite3
from collections import OrderedDict
from typing import Any


def _hash_key(namespace: str, key: str) -> str:
    return hashlib.sha256(f"{namespace}\x00{key}".encode("utf-8")).hexdigest()


class MemoryCache:
    def __init__(self, max_entries: int = 10_000):
        self.max_entries = max_entries
        self._store: "OrderedDict[str, tuple]" = OrderedDict()

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        k = _hash_key(namespace, key)
        entry = self._store.get(k)
        if entry is None:
            return default
        expires, value = entry
        if expires and expires < time.time():
            self._store.pop(k, None)
            return default
        self._store.move_to_end(k)
        return value

    def set(self, namespace: str, key: str, value: Any, ttl: float = 0.0) -> None:
        k = _hash_key(namespace, key)
        expires = time.time() + ttl if ttl > 0 else 0.0
        self._store[k] = (expires, value)
        self._store.move_to_end(k)
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def clear(self) -> None:
        self._store.clear()


class DiskCache:
    def __init__(self, directory: str = ".behavioral_cache"):
        self.directory = directory
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            pass

    def _path(self, namespace: str, key: str) -> str:
        return os.path.join(self.directory, _hash_key(namespace, key) + ".json")

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        path = self._path(namespace, key)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                entry = json.load(fh)
        except (OSError, ValueError):
            return default
        if entry.get("expires") and entry["expires"] < time.time():
            try:
                os.remove(path)
            except OSError:
                pass
            return default
        return entry.get("value", default)

    def set(self, namespace: str, key: str, value: Any, ttl: float = 0.0) -> None:
        expires = time.time() + ttl if ttl > 0 else 0.0
        try:
            with open(self._path(namespace, key), "w", encoding="utf-8") as fh:
                json.dump({"expires": expires, "value": value}, fh,
                          ensure_ascii=False)
        except (OSError, TypeError):
            pass

    def clear(self) -> None:
        try:
            for name in os.listdir(self.directory):
                if name.endswith(".json"):
                    os.remove(os.path.join(self.directory, name))
        except OSError:
            pass


class SQLiteCache:
    def __init__(self, db_path: str = "behavioral_intelligence.db"):
        self.db_path = db_path
        with self._conn() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS behavior_cache (
                namespace TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
                expires_at REAL NOT NULL DEFAULT 0, PRIMARY KEY (namespace,key))""")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT value,expires_at FROM behavior_cache WHERE namespace=? AND key=?",
                    (namespace, key)).fetchone()
            if not row:
                return default
            value, expires = row
            if expires and expires < time.time():
                with self._conn() as conn:
                    conn.execute("DELETE FROM behavior_cache WHERE namespace=? AND key=?",
                                (namespace, key))
                return default
            return json.loads(value)
        except (sqlite3.Error, ValueError):
            return default

    def set(self, namespace: str, key: str, value: Any, ttl: float = 0.0) -> None:
        expires = time.time() + ttl if ttl > 0 else 0.0
        try:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO behavior_cache (namespace,key,value,expires_at)
                       VALUES (?,?,?,?) ON CONFLICT(namespace,key) DO UPDATE SET
                       value=excluded.value, expires_at=excluded.expires_at""",
                    (namespace, key, json.dumps(value, ensure_ascii=False), expires))
        except (sqlite3.Error, TypeError):
            pass

    def clear(self) -> None:
        try:
            with self._conn() as conn:
                conn.execute("DELETE FROM behavior_cache")
        except sqlite3.Error:
            pass


class LayeredCache:
    """Memory over a persistent backend. Reads check memory first; a persistent
    hit is promoted into memory. Writes go to both."""

    def __init__(self, persistent=None, *, memory_entries: int = 10_000):
        self.memory = MemoryCache(memory_entries)
        self.persistent = persistent

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        sentinel = object()
        v = self.memory.get(namespace, key, sentinel)
        if v is not sentinel:
            return v
        if self.persistent is not None:
            v = self.persistent.get(namespace, key, sentinel)
            if v is not sentinel:
                self.memory.set(namespace, key, v)
                return v
        return default

    def set(self, namespace: str, key: str, value: Any, ttl: float = 0.0) -> None:
        self.memory.set(namespace, key, value, ttl)
        if self.persistent is not None:
            self.persistent.set(namespace, key, value, ttl)

    def clear(self) -> None:
        self.memory.clear()
        if self.persistent is not None:
            self.persistent.clear()
