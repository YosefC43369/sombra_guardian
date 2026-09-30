"""
cve_tracker.storage.migrations — standalone schema apply/verify helpers.

The *platform* migration lives in ``migrations/m0008_cve_tracker.py`` and runs
through the project's ``MigrationRunner`` at startup. This module provides the
same effect for contexts that don't go through that runner — tests, a CLI init,
or a defensive 'ensure my tables exist' call at engine start. Both paths share
the single DDL in :mod:`cve_tracker.storage.database`, so they can never drift.
"""

from __future__ import annotations

import logging

from ..version import SCHEMA_VERSION
from .database import connect, ensure_schema, drop_schema

logger = logging.getLogger("modbot.cve.migrations")

_META_KEY = "schema_version"


def apply(db_path: str) -> None:
    """Ensure all cve_ tables exist and stamp the schema version. Idempotent."""
    conn = connect(db_path)
    try:
        ensure_schema(conn)
        conn.execute(
            "INSERT INTO cve_meta(key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_META_KEY, str(SCHEMA_VERSION)))
        conn.commit()
        logger.info("CVE SCHEMA: OK (version %s)", SCHEMA_VERSION)
    finally:
        conn.close()


def current_version(db_path: str) -> int:
    conn = connect(db_path)
    try:
        row = conn.execute(
            "SELECT value FROM cve_meta WHERE key=?", (_META_KEY,)).fetchone()
        return int(row["value"]) if row else 0
    except Exception:
        return 0
    finally:
        conn.close()


def verify(db_path: str) -> bool:
    """True if every expected table is present."""
    from .database import CVE_TABLES
    conn = connect(db_path)
    try:
        existing = {
            r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        return all(t in existing for t in CVE_TABLES)
    finally:
        conn.close()


def teardown(db_path: str) -> None:
    """Drop every cve_ table — tests only."""
    conn = connect(db_path)
    try:
        drop_schema(conn)
    finally:
        conn.close()
