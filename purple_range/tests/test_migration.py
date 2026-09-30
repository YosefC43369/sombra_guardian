"""Migration 0007 creates the pr_* tables and verifies clean."""

from __future__ import annotations

import sqlite3

import migrations

EXPECTED = {"pr_plans", "pr_plan_steps", "pr_instantiations", "pr_coverage_snapshots"}


def test_creates_tables(legacy_db):
    conn = sqlite3.connect(legacy_db)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pr_%'")}
    conn.close()
    assert EXPECTED <= names


def test_runner_reaches_0007_and_verifies(legacy_db):
    runner = migrations.MigrationRunner(legacy_db)
    assert runner.current() == "0007"
    assert runner.verify() == []


def test_idempotent(legacy_db):
    # re-applying must not raise
    migrations.apply_startup_migrations(legacy_db)
