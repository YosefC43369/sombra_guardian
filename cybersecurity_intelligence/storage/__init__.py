"""
cybersecurity_intelligence.storage — durable persistence for the analytic layer.

Standard-library ``sqlite3`` only, matching ``threat_actor_intelligence.storage``
and ``entity_fusion.storage``: WAL journaling, a short-lived connection per
operation, ``CREATE TABLE IF NOT EXISTS`` with explicit indexes, and every record
stored as a lossless JSON ``data`` blob plus the scalar columns needed for query.
FTS5 is used for claim search when the runtime's SQLite provides it, with a LIKE
fallback so the store never hard-depends on it.
"""

from __future__ import annotations

from .store import CTIStore, DEFAULT_DB_PATH

__all__ = ["CTIStore", "DEFAULT_DB_PATH"]
