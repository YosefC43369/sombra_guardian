"""
cve_tracker.storage.database — sqlite connection + the single schema source.

The subsystem stores on the shared ``bot.db`` (rule §32: reuse the existing
store), using the same sqlite-per-module pattern as news.py/security.py. All DDL
lives here in :data:`CVE_SCHEMA` so there is exactly one definition, used both
by the platform migration (``migrations/m0008_cve_tracker.py``) and by
:func:`ensure_schema` for standalone/test init. Every statement is
``IF NOT EXISTS`` and additive — it never touches a non-``cve_`` table, so it is
safe to run against a database that already holds the bot's other tables
(rules §44, §45).

Tables (all ``cve_`` prefixed):
    cve_records         merged CVE (indexed columns + full JSON blob)
    cve_source_records  per-source raw payloads (provenance / reprocessing)
    cve_references      one row per reference URL (indexed search)
    cve_products        one row per affected vendor/product (indexed search)
    cve_cwes            one row per CWE association (indexed search)
    cve_source_state    per-source incremental cursor + rolling health
    cve_notifications   CVE→chat delivery records (idempotency)
    cve_subscriptions   per-chat notification preferences
    cve_ai_summaries    cached AI Thai summaries
    cve_events          internal domain-event log (change detection etc.)
    cve_ingestion_runs  one row per polling round (metrics)
    cve_failures        per-record ingest failures (audit)
    cve_audit_log       important operations (who/what/result)
    cve_meta            misc key/value (schema version, last full sync)
"""

from __future__ import annotations

import sqlite3
from typing import List

# Ordered DDL. Index creation follows its table. Kept as individual statements
# so the migration can execute them one-by-one inside its transaction.
CVE_SCHEMA: List[str] = [
    # ---------- core record ----------
    """CREATE TABLE IF NOT EXISTS cve_records (
        cve_id           TEXT PRIMARY KEY,
        title            TEXT,
        description      TEXT,
        published_at     INTEGER,
        last_modified_at INTEGER,
        severity         TEXT,
        cvss_score       REAL,
        cvss_version     TEXT,
        kev              INTEGER NOT NULL DEFAULT 0,
        exploit_maturity TEXT,
        priority         TEXT,
        priority_score   INTEGER NOT NULL DEFAULT 0,
        ai_state         TEXT,
        source_count     INTEGER NOT NULL DEFAULT 0,
        content_hash     TEXT,
        first_seen_at    INTEGER NOT NULL,
        enriched_at      INTEGER,
        updated_at       INTEGER NOT NULL,
        data             TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_published ON cve_records(published_at)",
    "CREATE INDEX IF NOT EXISTS ix_cve_modified ON cve_records(last_modified_at)",
    "CREATE INDEX IF NOT EXISTS ix_cve_severity ON cve_records(severity)",
    "CREATE INDEX IF NOT EXISTS ix_cve_cvss ON cve_records(cvss_score)",
    "CREATE INDEX IF NOT EXISTS ix_cve_kev ON cve_records(kev)",
    "CREATE INDEX IF NOT EXISTS ix_cve_priority ON cve_records(priority_score)",
    "CREATE INDEX IF NOT EXISTS ix_cve_ai_state ON cve_records(ai_state)",
    "CREATE INDEX IF NOT EXISTS ix_cve_first_seen ON cve_records(first_seen_at)",

    # ---------- per-source raw ----------
    """CREATE TABLE IF NOT EXISTS cve_source_records (
        cve_id      TEXT NOT NULL,
        source      TEXT NOT NULL,
        source_id   TEXT,
        source_url  TEXT,
        fetched_at  INTEGER NOT NULL,
        raw         TEXT,
        PRIMARY KEY (cve_id, source)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_srcrec_source ON cve_source_records(source)",

    # ---------- references ----------
    """CREATE TABLE IF NOT EXISTS cve_references (
        cve_id   TEXT NOT NULL,
        url      TEXT NOT NULL,
        ref_type TEXT,
        source   TEXT,
        PRIMARY KEY (cve_id, url)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_ref_type ON cve_references(ref_type)",

    # ---------- products ----------
    """CREATE TABLE IF NOT EXISTS cve_products (
        cve_id      TEXT NOT NULL,
        vendor      TEXT,
        product     TEXT,
        vendor_key  TEXT,
        product_key TEXT,
        PRIMARY KEY (cve_id, vendor_key, product_key)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_prod_vendor ON cve_products(vendor_key)",
    "CREATE INDEX IF NOT EXISTS ix_cve_prod_product ON cve_products(product_key)",

    # ---------- cwes ----------
    """CREATE TABLE IF NOT EXISTS cve_cwes (
        cve_id TEXT NOT NULL,
        cwe_id TEXT NOT NULL,
        PRIMARY KEY (cve_id, cwe_id)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_cwe ON cve_cwes(cwe_id)",

    # ---------- source state ----------
    """CREATE TABLE IF NOT EXISTS cve_source_state (
        source               TEXT PRIMARY KEY,
        enabled              INTEGER NOT NULL DEFAULT 1,
        last_success_at      INTEGER,
        last_failure_at      INTEGER,
        last_cursor          TEXT,
        last_modified_seen   INTEGER,
        etag                 TEXT,
        http_last_modified   TEXT,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        total_runs           INTEGER NOT NULL DEFAULT 0,
        records_seen         INTEGER NOT NULL DEFAULT 0,
        records_new          INTEGER NOT NULL DEFAULT 0,
        records_updated      INTEGER NOT NULL DEFAULT 0,
        records_duplicate    INTEGER NOT NULL DEFAULT 0,
        last_latency_ms      INTEGER NOT NULL DEFAULT 0,
        health               TEXT,
        last_error           TEXT
    )""",

    # ---------- notifications ----------
    """CREATE TABLE IF NOT EXISTS cve_notifications (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        dedupe_key  TEXT NOT NULL UNIQUE,
        cve_id      TEXT NOT NULL,
        chat_id     INTEGER NOT NULL,
        topic_id    INTEGER,
        reason      TEXT,
        state       TEXT NOT NULL,
        priority    TEXT,
        is_update   INTEGER NOT NULL DEFAULT 0,
        attempts    INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL,
        sent_at     INTEGER,
        error       TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_notif_cve ON cve_notifications(cve_id)",
    "CREATE INDEX IF NOT EXISTS ix_cve_notif_chat ON cve_notifications(chat_id)",
    "CREATE INDEX IF NOT EXISTS ix_cve_notif_state ON cve_notifications(state)",

    # ---------- subscriptions ----------
    """CREATE TABLE IF NOT EXISTS cve_subscriptions (
        chat_id     INTEGER NOT NULL,
        topic_id    INTEGER NOT NULL DEFAULT 0,
        enabled     INTEGER NOT NULL DEFAULT 1,
        data        TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        updated_at  INTEGER NOT NULL,
        PRIMARY KEY (chat_id, topic_id)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_sub_enabled ON cve_subscriptions(enabled)",

    # ---------- ai summaries ----------
    """CREATE TABLE IF NOT EXISTS cve_ai_summaries (
        cve_id     TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        language   TEXT NOT NULL DEFAULT 'th',
        data       TEXT NOT NULL,
        provider   TEXT,
        model      TEXT,
        fallback   INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (cve_id, input_hash)
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_ai_created ON cve_ai_summaries(created_at)",

    # ---------- events ----------
    """CREATE TABLE IF NOT EXISTS cve_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id     TEXT,
        event_type TEXT NOT NULL,
        payload    TEXT,
        created_at INTEGER NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_events_cve ON cve_events(cve_id)",
    "CREATE INDEX IF NOT EXISTS ix_cve_events_type ON cve_events(event_type, created_at)",

    # ---------- ingestion runs ----------
    """CREATE TABLE IF NOT EXISTS cve_ingestion_runs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at     INTEGER NOT NULL,
        finished_at    INTEGER,
        sources        TEXT,
        records_seen   INTEGER NOT NULL DEFAULT 0,
        records_new    INTEGER NOT NULL DEFAULT 0,
        records_updated INTEGER NOT NULL DEFAULT 0,
        records_failed INTEGER NOT NULL DEFAULT 0,
        ok             INTEGER NOT NULL DEFAULT 1,
        note           TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_runs_started ON cve_ingestion_runs(started_at)",

    # ---------- failures ----------
    """CREATE TABLE IF NOT EXISTS cve_failures (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        source     TEXT,
        cve_id     TEXT,
        reason     TEXT,
        created_at INTEGER NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_fail_created ON cve_failures(created_at)",

    # ---------- audit ----------
    """CREATE TABLE IF NOT EXISTS cve_audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        at         INTEGER NOT NULL,
        actor      TEXT,
        event      TEXT NOT NULL,
        cve_id     TEXT,
        result     TEXT,
        metadata   TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_cve_audit_at ON cve_audit_log(at)",
    "CREATE INDEX IF NOT EXISTS ix_cve_audit_event ON cve_audit_log(event, at)",

    # ---------- meta ----------
    """CREATE TABLE IF NOT EXISTS cve_meta (
        key   TEXT PRIMARY KEY,
        value TEXT
    )""",
]

# Tables owned by this subsystem — used by a (non-default) downgrade and by
# test teardown. Order is child-before-parent though there are no FK cascades.
CVE_TABLES = [
    "cve_source_records", "cve_references", "cve_products", "cve_cwes",
    "cve_notifications", "cve_subscriptions", "cve_ai_summaries", "cve_events",
    "cve_ingestion_runs", "cve_failures", "cve_audit_log", "cve_source_state",
    "cve_meta", "cve_records",
]


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection tuned like the rest of the bot's sqlite usage: Row
    factory for name access, a busy timeout so concurrent writers wait instead
    of erroring, and WAL for better read/write concurrency with the main bot."""
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
    except sqlite3.Error:
        # PRAGMAs are best-effort; a read-only or older sqlite still works.
        pass
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create every ``cve_`` table/index if absent. Idempotent and additive —
    safe to call at startup even when the migration already ran."""
    cur = conn.cursor()
    for stmt in CVE_SCHEMA:
        cur.execute(stmt)
    conn.commit()


def drop_schema(conn: sqlite3.Connection) -> None:
    """Drop every ``cve_`` table. Used ONLY by an explicit migration downgrade
    or test teardown — never at runtime."""
    cur = conn.cursor()
    for table in CVE_TABLES:
        cur.execute(f"DROP TABLE IF EXISTS {table}")
    conn.commit()
