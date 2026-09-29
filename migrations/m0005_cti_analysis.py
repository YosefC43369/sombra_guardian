"""
migrations/m0005_cti_analysis.py — schema for the CTI Analysis Engine (v2.0).

Centralized, versioned registration of the ``cti_`` tables owned by the
``cybersecurity_intelligence`` package (graded sources, consolidated claims,
contradictions, finished assessments). Following the repo's dual pattern
(documented in ``migrations/__init__.py``): the ``CTIStore`` still self-initializes
these tables with ``CREATE TABLE IF NOT EXISTS`` for zero-config startup, and this
migration is the auditable record of the same schema so an operator can see and
roll it back centrally.

All tables are ``cti_``-prefixed, created IF NOT EXISTS, indexed by the real access
patterns (subject lookup, type filter, priority filter), non-destructive and
reversible. The runtime FTS5 search table is intentionally *not* created here — it
is probed and created at runtime because FTS5 availability is a build-time property
of the host's SQLite, not a schema fact.
"""

from .base import Migration


class CTIAnalysisMigration(Migration):
    version = "0005"
    description = "CTI Analysis Engine v2.0: graded sources, claims, contradictions, assessments"
    destructive = False

    def upgrade(self, conn) -> None:
        c = conn.execute

        c("""CREATE TABLE IF NOT EXISTS cti_sources (
            source_id    TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            source_class TEXT NOT NULL DEFAULT 'unknown',
            grade        TEXT NOT NULL DEFAULT 'unknown',
            score        REAL NOT NULL DEFAULT 0,
            first_seen   REAL NOT NULL DEFAULT 0,
            last_seen    REAL NOT NULL DEFAULT 0,
            data         TEXT NOT NULL,
            updated_at   REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_cti_sources_name ON cti_sources(name)")
        c("CREATE INDEX IF NOT EXISTS ix_cti_sources_grade ON cti_sources(grade)")

        c("""CREATE TABLE IF NOT EXISTS cti_claims (
            claim_id            TEXT PRIMARY KEY,
            subject_type        TEXT NOT NULL,
            subject_value       TEXT NOT NULL,
            subject_key         TEXT NOT NULL,
            claim_type          TEXT NOT NULL,
            predicate           TEXT DEFAULT '',
            score               REAL NOT NULL DEFAULT 0,
            band                TEXT DEFAULT 'very low',
            independent_sources INTEGER NOT NULL DEFAULT 0,
            observed_at         REAL NOT NULL DEFAULT 0,
            first_seen          REAL NOT NULL DEFAULT 0,
            last_seen           REAL NOT NULL DEFAULT 0,
            data                TEXT NOT NULL,
            updated_at          REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_cti_claims_subject ON cti_claims(subject_key)")
        c("CREATE INDEX IF NOT EXISTS ix_cti_claims_type ON cti_claims(claim_type)")
        c("CREATE INDEX IF NOT EXISTS ix_cti_claims_subjtype ON cti_claims(subject_type)")

        c("""CREATE TABLE IF NOT EXISTS cti_contradictions (
            contradiction_id   TEXT PRIMARY KEY,
            contradiction_type TEXT NOT NULL,
            subject_key        TEXT NOT NULL,
            data               TEXT NOT NULL,
            detected_at        REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_cti_contra_subject ON cti_contradictions(subject_key)")
        c("CREATE INDEX IF NOT EXISTS ix_cti_contra_type ON cti_contradictions(contradiction_type)")

        c("""CREATE TABLE IF NOT EXISTS cti_assessments (
            assessment_id TEXT PRIMARY KEY,
            subject_key   TEXT NOT NULL,
            title         TEXT NOT NULL,
            priority      TEXT NOT NULL DEFAULT 'informational',
            score         REAL NOT NULL DEFAULT 0,
            band          TEXT DEFAULT 'very low',
            data          TEXT NOT NULL,
            created_at    REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_cti_assess_subject ON cti_assessments(subject_key)")
        c("CREATE INDEX IF NOT EXISTS ix_cti_assess_priority ON cti_assessments(priority)")

    def downgrade(self, conn) -> None:
        for table in ("cti_sources", "cti_claims", "cti_contradictions",
                      "cti_assessments"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
