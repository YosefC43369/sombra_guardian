"""
geo_osint.storage — persistence and indexing (spec §51).

  * :class:`GeoGridIndex` — in-memory uniform-grid spatial index for O(k) radius/
    nearest queries at scale;
  * :class:`SQLiteGeoStore` — durable observation storage with R*Tree acceleration
    (scan fallback), chunked streaming inserts;
  * :class:`CacheStore` — TTL disk cache for polite reuse of public-source
    responses.

All pure stdlib.
"""

from .geo_index import GeoGridIndex
from .sqlite_store import SQLiteGeoStore
from .cache_store import CacheStore

__all__ = ["GeoGridIndex", "SQLiteGeoStore", "CacheStore"]
