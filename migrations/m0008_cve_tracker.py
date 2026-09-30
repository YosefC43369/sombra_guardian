"""
migrations/m0008_cve_tracker.py — schema for the CVE Intelligence subsystem.

Every table is ``cve_``-prefixed, created with ``IF NOT EXISTS`` and additive —
NON-destructive and reversible. The DDL is NOT duplicated here: it is the single
definition in :data:`cve_tracker.storage.database.CVE_SCHEMA`, so the platform
migration and the subsystem's standalone ``ensure_schema`` can never drift
(rules §44, §45). This migration only touches ``cve_`` tables; it never alters
or drops any existing bot table.
"""

from .base import Migration


class CVETrackerMigration(Migration):
    version = "0008"
    description = "CVE Intelligence & Tracking: records, sources, refs, products, cwes, notifications, subscriptions, ai summaries, events, runs, failures, audit, meta"
    destructive = False

    def upgrade(self, conn) -> None:
        # Import here (not at module top) so migration *discovery* never fails
        # if the cve_tracker package is temporarily unavailable — the runner
        # logs and skips a module that can't import, and we'd rather this one
        # import lazily at apply time.
        from cve_tracker.storage.database import CVE_SCHEMA
        from cve_tracker.version import SCHEMA_VERSION

        cur = conn.cursor()
        for stmt in CVE_SCHEMA:
            cur.execute(stmt)
        cur.execute(
            "INSERT INTO cve_meta(key,value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )

    def downgrade(self, conn) -> None:
        from cve_tracker.storage.database import CVE_TABLES
        for table in CVE_TABLES:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
