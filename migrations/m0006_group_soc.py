"""
migrations/m0006_group_soc.py — schema for the Group Security Operations Center.

Every table is:
  * ``soc_``-prefixed to namespace it away from the legacy schema,
  * chat-scoped (``chat_id`` present and indexed) so nothing leaks across groups,
  * created with ``IF NOT EXISTS`` and paired with a real ``downgrade`` — this
    migration is NON-destructive and reversible.

Only DDL here; no data is read or written. Query paths use parameterized SQL and
open connections in WAL mode (set in ``group_soc.storage.repository``), not here.

Privacy (rule §17): user identities are stored as salted hashes (``actor_hash``),
message content as a hash + length, never raw ids/text.
"""

from .base import Migration


class GroupSocMigration(Migration):
    version = "0006"
    description = "Group SOC: events, signals, alerts, cases, incidents, timeline, watchlist, audit"
    destructive = False

    _TABLES = (
        "soc_events", "soc_signals", "soc_alerts", "soc_cases", "soc_case_notes",
        "soc_incidents", "soc_timeline", "soc_watchlist", "soc_investigations",
        "soc_evidence_links", "soc_audit_log", "soc_group_policy",
    )

    def upgrade(self, conn) -> None:
        c = conn.execute

        # ---- normalized security events (the SOC's atomic record) ----
        c("""CREATE TABLE IF NOT EXISTS soc_events (
            event_id       TEXT PRIMARY KEY,
            event_type     TEXT NOT NULL,
            ts             INTEGER NOT NULL,
            chat_id        INTEGER NOT NULL,
            source         TEXT NOT NULL DEFAULT 'telegram',
            correlation_id TEXT,
            actor_hash     TEXT,
            target_hash    TEXT,
            object_type    TEXT NOT NULL DEFAULT 'none',
            object_id      TEXT,
            content_hash   TEXT,
            content_len    INTEGER NOT NULL DEFAULT 0,
            severity       TEXT NOT NULL DEFAULT 'info',
            confidence     REAL NOT NULL DEFAULT 0.0,
            analytic_state TEXT NOT NULL DEFAULT 'observed',
            entities       TEXT,
            context        TEXT,
            metadata       TEXT,
            schema_version INTEGER NOT NULL DEFAULT 1
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_events_chat_ts ON soc_events(chat_id, ts)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_events_chat_type_ts ON soc_events(chat_id, event_type, ts)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_events_corr ON soc_events(correlation_id)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_events_actor ON soc_events(chat_id, actor_hash, ts)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_events_chash ON soc_events(chat_id, content_hash, ts)")

        # ---- security signals (correlation/detection output) ----
        c("""CREATE TABLE IF NOT EXISTS soc_signals (
            signal_id      TEXT PRIMARY KEY,
            signal_type    TEXT NOT NULL,
            producer       TEXT NOT NULL DEFAULT '',
            chat_id        INTEGER NOT NULL,
            ts             INTEGER NOT NULL,
            correlation_id TEXT,
            title          TEXT NOT NULL DEFAULT '',
            summary        TEXT NOT NULL DEFAULT '',
            dimensions     TEXT,
            analytic_state TEXT NOT NULL DEFAULT 'correlated',
            event_ids      TEXT,
            entities       TEXT,
            dedup_key      TEXT NOT NULL DEFAULT '',
            metadata       TEXT,
            schema_version INTEGER NOT NULL DEFAULT 1
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_signals_chat_ts ON soc_signals(chat_id, ts)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_signals_dedup ON soc_signals(chat_id, dedup_key, ts)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_signals_corr ON soc_signals(correlation_id)")

        # ---- alerts ----
        c("""CREATE TABLE IF NOT EXISTS soc_alerts (
            alert_id       TEXT PRIMARY KEY,
            chat_id        INTEGER NOT NULL,
            correlation_id TEXT,
            signal_id      TEXT,
            dedup_key      TEXT NOT NULL DEFAULT '',
            title          TEXT NOT NULL DEFAULT '',
            summary        TEXT NOT NULL DEFAULT '',
            severity       TEXT NOT NULL DEFAULT 'medium',
            priority_band  TEXT NOT NULL DEFAULT 'P3',
            priority_score REAL NOT NULL DEFAULT 0.0,
            status         TEXT NOT NULL DEFAULT 'new',
            assignee_hash  TEXT,
            hit_count      INTEGER NOT NULL DEFAULT 1,
            group_id       TEXT,
            created_at     INTEGER NOT NULL,
            updated_at     INTEGER NOT NULL,
            last_seen_at   INTEGER NOT NULL,
            acknowledged_at INTEGER,
            resolved_at    INTEGER,
            signal_ids     TEXT,
            metadata       TEXT,
            schema_version INTEGER NOT NULL DEFAULT 1
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_alerts_chat_status ON soc_alerts(chat_id, status, updated_at)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_alerts_dedup ON soc_alerts(chat_id, dedup_key, status)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_alerts_corr ON soc_alerts(correlation_id)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_alerts_group ON soc_alerts(group_id)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_alerts_prio ON soc_alerts(chat_id, priority_score)")

        # ---- cases ----
        c("""CREATE TABLE IF NOT EXISTS soc_cases (
            case_id        TEXT PRIMARY KEY,
            chat_id        INTEGER NOT NULL,
            title          TEXT NOT NULL DEFAULT '',
            summary        TEXT NOT NULL DEFAULT '',
            severity       TEXT NOT NULL DEFAULT 'medium',
            status         TEXT NOT NULL DEFAULT 'open',
            assignee_hash  TEXT,
            opened_by_hash TEXT,
            alert_ids      TEXT,
            incident_id    TEXT,
            created_at     INTEGER NOT NULL,
            updated_at     INTEGER NOT NULL,
            closed_at      INTEGER,
            metadata       TEXT,
            schema_version INTEGER NOT NULL DEFAULT 1
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_cases_chat_status ON soc_cases(chat_id, status, updated_at)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_cases_assignee ON soc_cases(assignee_hash)")

        c("""CREATE TABLE IF NOT EXISTS soc_case_notes (
            note_id     TEXT PRIMARY KEY,
            case_id     TEXT NOT NULL,
            ts          INTEGER NOT NULL,
            author_hash TEXT,
            text        TEXT NOT NULL DEFAULT ''
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_case_notes_case ON soc_case_notes(case_id, ts)")

        # ---- incidents (SOC-level aggregate; bridges to member_incident) ----
        c("""CREATE TABLE IF NOT EXISTS soc_incidents (
            incident_id       TEXT PRIMARY KEY,
            chat_id           INTEGER NOT NULL,
            title             TEXT NOT NULL DEFAULT '',
            summary           TEXT NOT NULL DEFAULT '',
            classification    TEXT NOT NULL DEFAULT 'other',
            severity          TEXT NOT NULL DEFAULT 'high',
            status            TEXT NOT NULL DEFAULT 'open',
            dimensions        TEXT,
            alert_ids         TEXT,
            case_ids          TEXT,
            correlation_ids   TEXT,
            opened_by_hash    TEXT,
            member_incident_id INTEGER,
            created_at        INTEGER NOT NULL,
            updated_at        INTEGER NOT NULL,
            resolved_at       INTEGER,
            resolution        TEXT NOT NULL DEFAULT '',
            metadata          TEXT,
            schema_version    INTEGER NOT NULL DEFAULT 1
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_incidents_chat_status ON soc_incidents(chat_id, status, updated_at)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_incidents_member ON soc_incidents(member_incident_id)")

        # ---- reconstructed timelines (durable copies for incident records) ----
        c("""CREATE TABLE IF NOT EXISTS soc_timeline (
            entry_id       TEXT PRIMARY KEY,
            chat_id        INTEGER NOT NULL,
            ts             INTEGER NOT NULL,
            kind           TEXT NOT NULL DEFAULT 'event',
            ref_id         TEXT NOT NULL DEFAULT '',
            correlation_id TEXT,
            actor_hash     TEXT,
            summary        TEXT NOT NULL DEFAULT '',
            metadata       TEXT
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_timeline_chat_ts ON soc_timeline(chat_id, ts)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_timeline_corr ON soc_timeline(correlation_id, ts)")

        # ---- watchlist (monitoring targets; NOT a malicious verdict) ----
        c("""CREATE TABLE IF NOT EXISTS soc_watchlist (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id      INTEGER NOT NULL,
            kind         TEXT NOT NULL,
            value        TEXT NOT NULL,
            note         TEXT,
            severity     TEXT NOT NULL DEFAULT 'medium',
            active       INTEGER NOT NULL DEFAULT 1,
            added_by_hash TEXT,
            added_at     INTEGER NOT NULL,
            expires_at   INTEGER,
            UNIQUE(chat_id, kind, value)
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_watchlist_lookup ON soc_watchlist(chat_id, kind, active)")

        # ---- investigations ----
        c("""CREATE TABLE IF NOT EXISTS soc_investigations (
            investigation_id TEXT PRIMARY KEY,
            chat_id        INTEGER NOT NULL,
            case_id        TEXT,
            title          TEXT NOT NULL DEFAULT '',
            state          TEXT NOT NULL DEFAULT 'open',
            hypotheses     TEXT,
            findings       TEXT,
            conclusion     TEXT,
            opened_by_hash TEXT,
            created_at     INTEGER NOT NULL,
            updated_at     INTEGER NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_investig_chat ON soc_investigations(chat_id, state)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_investig_case ON soc_investigations(case_id)")

        # ---- evidence links (generic: attach any ref to case/incident/investigation) ----
        c("""CREATE TABLE IF NOT EXISTS soc_evidence_links (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id      INTEGER NOT NULL,
            owner_kind   TEXT NOT NULL,          -- case|incident|investigation
            owner_id     TEXT NOT NULL,
            ref_kind     TEXT NOT NULL,          -- event|signal|alert|external
            ref_id       TEXT NOT NULL,
            note         TEXT,
            added_by_hash TEXT,
            added_at     INTEGER NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_evlinks_owner ON soc_evidence_links(owner_kind, owner_id)")

        # ---- audit log (every state change; retention-governed) ----
        c("""CREATE TABLE IF NOT EXISTS soc_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id     INTEGER NOT NULL,
            ts          INTEGER NOT NULL,
            actor_hash  TEXT,
            action      TEXT NOT NULL,
            target_kind TEXT,
            target_id   TEXT,
            detail      TEXT
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_soc_audit_chat_ts ON soc_audit_log(chat_id, ts)")
        c("CREATE INDEX IF NOT EXISTS ix_soc_audit_target ON soc_audit_log(target_kind, target_id)")

        # ---- per-group activation policy (safe default: inactive) ----
        c("""CREATE TABLE IF NOT EXISTS soc_group_policy (
            chat_id    INTEGER PRIMARY KEY,
            enabled    INTEGER NOT NULL DEFAULT 0,
            mode       TEXT NOT NULL DEFAULT 'monitor',   -- monitor|alert
            settings   TEXT,
            updated_at INTEGER NOT NULL,
            updated_by INTEGER
        )""")

    def downgrade(self, conn) -> None:
        for table in reversed(self._TABLES):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
