"""The m0005 CTI-analysis migration applies and rolls back cleanly, and is
discovered by the central runner without version collisions."""

from __future__ import annotations

import sqlite3

from migrations.m0005_cti_analysis import CTIAnalysisMigration
from migrations.runner import discover_migrations

_TABLES = ("cti_sources", "cti_claims", "cti_contradictions", "cti_assessments")


def _table_names(conn):
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}


def test_migration_upgrade_creates_tables(tmp_path):
    db = str(tmp_path / "m.db")
    conn = sqlite3.connect(db)
    try:
        CTIAnalysisMigration().upgrade(conn)
        conn.commit()
        names = _table_names(conn)
        for t in _TABLES:
            assert t in names
    finally:
        conn.close()


def test_migration_downgrade_drops_tables(tmp_path):
    db = str(tmp_path / "m.db")
    conn = sqlite3.connect(db)
    try:
        m = CTIAnalysisMigration()
        m.upgrade(conn)
        conn.commit()
        m.downgrade(conn)
        conn.commit()
        names = _table_names(conn)
        for t in _TABLES:
            assert t not in names
    finally:
        conn.close()


def test_migration_is_discovered_and_versioned():
    migrations = discover_migrations("migrations")
    versions = [m.version for m in migrations]
    assert "0005" in versions
    # no duplicate versions (discover would raise, but assert the invariant too)
    assert len(versions) == len(set(versions))


def test_migration_non_destructive():
    assert CTIAnalysisMigration().destructive is False
