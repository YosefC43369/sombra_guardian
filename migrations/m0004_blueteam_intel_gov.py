"""
migrations/m0004_blueteam_intel_gov.py — schema for v0.8.0 Blue Team Intelligence &
Governance (Threat Intel/IOC, Detection-as-Code, Posture).

All tables are ``bt_``-prefixed, keyed/indexed by chat_id or tenant_id for
isolation, created IF NOT EXISTS, and paired with a real ``downgrade``.
Non-destructive and reversible. Indexes follow the real access patterns (lookup by
type, sightings by ioc/chat+time, rule hits by rule+time, rollup by chat+metric+hour).
"""

from .base import Migration


class IntelGovMigration(Migration):
    version = "0004"
    description = "Blue Team v0.8: threat intel/IOC, detection-as-code, posture"
    destructive = False

    def upgrade(self, conn) -> None:
        c = conn.execute

        # ---------------- platform: job scheduler ----------------
        c("""CREATE TABLE IF NOT EXISTS bt_job (
            name          TEXT PRIMARY KEY,
            next_run      REAL NOT NULL DEFAULT 0,
            locked_until  REAL NOT NULL DEFAULT 0,
            last_run      REAL,
            last_status   TEXT
        )""")

        # ---------------- Intel ----------------
        c("""CREATE TABLE IF NOT EXISTS bt_ioc (
            ioc_id     TEXT PRIMARY KEY,          -- sha256(type|canonical)
            ioc_type   TEXT NOT NULL,
            value      TEXT NOT NULL,             -- canonical value
            sources    TEXT,                      -- comma-joined feed names
            first_seen REAL NOT NULL,
            last_seen  REAL NOT NULL,
            expires_at REAL,
            confidence INTEGER NOT NULL DEFAULT 50,
            severity   TEXT NOT NULL DEFAULT 'medium',
            tlp        TEXT NOT NULL DEFAULT 'amber',
            tags       TEXT,
            attack     TEXT,
            family     TEXT,
            provenance TEXT,                       -- JSON breakdown
            is_local   INTEGER NOT NULL DEFAULT 0  -- admin/feedback-derived
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_ioc_type ON bt_ioc(ioc_type)")
        c("CREATE INDEX IF NOT EXISTS ix_bt_ioc_expires ON bt_ioc(expires_at)")

        c("""CREATE TABLE IF NOT EXISTS bt_ioc_sighting (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id   TEXT NOT NULL,
            chat_id  INTEGER,
            user_id  INTEGER,
            context  TEXT,
            seen_at  REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_sight_ioc ON bt_ioc_sighting(ioc_id, seen_at)")
        c("CREATE INDEX IF NOT EXISTS ix_bt_sight_chat ON bt_ioc_sighting(chat_id, seen_at)")

        c("""CREATE TABLE IF NOT EXISTS bt_feed_state (
            feed            TEXT PRIMARY KEY,
            url             TEXT,
            etag            TEXT,
            last_modified   TEXT,
            last_sync       REAL,
            last_status     TEXT,
            item_count      INTEGER NOT NULL DEFAULT 0,
            circuit_state   TEXT NOT NULL DEFAULT 'closed',
            failures        INTEGER NOT NULL DEFAULT 0,
            enabled         INTEGER NOT NULL DEFAULT 1
        )""")

        c("""CREATE TABLE IF NOT EXISTS bt_intel_whitelist (
            value    TEXT PRIMARY KEY,             -- registrable domain / value never blocked
            added_by INTEGER,
            added_at REAL NOT NULL
        )""")

        # ---------------- Detection-as-Code ----------------
        c("""CREATE TABLE IF NOT EXISTS bt_rule (
            rule_id       TEXT PRIMARY KEY,
            title         TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'experimental',
            level         TEXT NOT NULL DEFAULT 'medium',
            logsource     TEXT NOT NULL DEFAULT 'message',
            version       TEXT NOT NULL DEFAULT '1.0.0',
            state         TEXT NOT NULL DEFAULT 'disabled',   -- disabled|shadow|canary|enabled
            canary_chats  TEXT,                                -- JSON list
            tags          TEXT,
            cooldown_s    INTEGER NOT NULL DEFAULT 0,
            dedupe_field  TEXT,
            updated_at    REAL NOT NULL,
            updated_by    INTEGER
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_rule_state ON bt_rule(state)")

        c("""CREATE TABLE IF NOT EXISTS bt_rule_version (
            rule_id    TEXT NOT NULL,
            version    TEXT NOT NULL,
            body       TEXT NOT NULL,             -- JSON rule source
            sha256     TEXT NOT NULL,
            author     TEXT,
            created_at REAL NOT NULL,
            notes      TEXT,
            PRIMARY KEY (rule_id, version)
        )""")

        c("""CREATE TABLE IF NOT EXISTS bt_rule_hit (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id   TEXT NOT NULL,
            chat_id   INTEGER,
            user_id   INTEGER,
            mode      TEXT NOT NULL DEFAULT 'enabled',
            matched_at REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_hit_rule ON bt_rule_hit(rule_id, matched_at)")
        c("CREATE INDEX IF NOT EXISTS ix_bt_hit_chat ON bt_rule_hit(chat_id, matched_at)")

        c("""CREATE TABLE IF NOT EXISTS bt_rule_cooldown (
            rule_id    TEXT NOT NULL,
            chat_id    INTEGER NOT NULL,
            dedupe_key TEXT NOT NULL,
            until      REAL NOT NULL,
            PRIMARY KEY (rule_id, chat_id, dedupe_key)
        )""")

        # ---------------- Posture / tenancy ----------------
        c("""CREATE TABLE IF NOT EXISTS bt_tenant (
            tenant_id    TEXT PRIMARY KEY,
            name         TEXT,
            brand_name   TEXT,
            brand_color  TEXT DEFAULT '#0b3d5c',
            brand_footer TEXT,
            created_at   REAL NOT NULL
        )""")
        c("""CREATE TABLE IF NOT EXISTS bt_tenant_group (
            tenant_id TEXT NOT NULL,
            chat_id   INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, chat_id)
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_tgroup_chat ON bt_tenant_group(chat_id)")
        c("""CREATE TABLE IF NOT EXISTS bt_tenant_role (
            tenant_id TEXT NOT NULL,
            user_id   INTEGER NOT NULL,
            role      TEXT NOT NULL DEFAULT 'viewer',
            PRIMARY KEY (tenant_id, user_id)
        )""")

        c("""CREATE TABLE IF NOT EXISTS bt_posture_rollup (
            chat_id   INTEGER NOT NULL,
            metric    TEXT NOT NULL,
            hour      INTEGER NOT NULL,           -- epoch hour bucket
            value     REAL NOT NULL DEFAULT 0,
            count     INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (chat_id, metric, hour)
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_rollup_chat ON bt_posture_rollup(chat_id, metric, hour)")

        c("""CREATE TABLE IF NOT EXISTS bt_posture_snapshot (
            snapshot_id TEXT PRIMARY KEY,
            tenant_id   TEXT,
            chat_id     INTEGER,
            score       REAL NOT NULL,
            grade       TEXT NOT NULL,
            coverage    REAL NOT NULL,
            breakdown   TEXT,                      -- JSON
            created_at  REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_snap_chat ON bt_posture_snapshot(chat_id, created_at)")

        c("""CREATE TABLE IF NOT EXISTS bt_report (
            report_id  TEXT PRIMARY KEY,
            tenant_id  TEXT,
            chat_id    INTEGER,
            profile    TEXT NOT NULL DEFAULT 'internal',
            fmt        TEXT NOT NULL DEFAULT 'html',
            sha256     TEXT NOT NULL,
            created_at REAL NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_report_chat ON bt_report(chat_id, created_at)")

    def downgrade(self, conn) -> None:
        for table in ("bt_job", "bt_ioc", "bt_ioc_sighting", "bt_feed_state",
                      "bt_intel_whitelist", "bt_rule", "bt_rule_version",
                      "bt_rule_hit", "bt_rule_cooldown", "bt_tenant",
                      "bt_tenant_group", "bt_tenant_role", "bt_posture_rollup",
                      "bt_posture_snapshot", "bt_report"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
