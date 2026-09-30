"""The 0006 migration creates every soc_* table + indexes and verifies clean."""

from __future__ import annotations

import sqlite3

import migrations


EXPECTED_TABLES = {
    "soc_events", "soc_signals", "soc_alerts", "soc_cases", "soc_case_notes",
    "soc_incidents", "soc_timeline", "soc_watchlist", "soc_investigations",
    "soc_evidence_links", "soc_audit_log", "soc_group_policy",
}


def test_migration_creates_tables(db_path):
    conn = sqlite3.connect(db_path)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'soc_%'")}
    conn.close()
    assert EXPECTED_TABLES <= names


def test_migration_creates_indexes(db_path):
    conn = sqlite3.connect(db_path)
    idx = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'ix_soc_%'")}
    conn.close()
    assert len(idx) >= 20


def test_runner_reaches_0006_and_verifies(db_path):
    runner = migrations.MigrationRunner(db_path)
    assert runner.current() == "0006"
    assert runner.verify() == []


def test_migration_is_idempotent(db_path):
    # applying again must not error (IF NOT EXISTS everywhere)
    status = migrations.apply_startup_migrations(db_path)
    assert isinstance(status, (list, dict))
