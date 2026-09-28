"""
geo_osint.cache — convenience façade over the storage cache (spec §51).

Re-exports :class:`geo_osint.storage.cache_store.CacheStore` at the package top
level and provides a process-wide default instance so any subsystem can share one
polite disk cache for public-source responses without threading it through every
constructor.
"""

from __future__ import annotations

from typing import Optional

from .storage.cache_store import CacheStore

_DEFAULT: Optional[CacheStore] = None


def default_cache() -> CacheStore:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = CacheStore()
    return _DEFAULT


def configure_cache(directory: str = "", default_ttl_s: float = 86400.0) -> CacheStore:
    global _DEFAULT
    _DEFAULT = CacheStore(directory, default_ttl_s)
    return _DEFAULT


__all__ = ["CacheStore", "default_cache", "configure_cache"]
