"""
migrations/m0003_blueteam.py — schema for the Blue Team Suite v0.7.0
(Link Guard, Scam/Impersonation, Join Guard / Anti-Raid).

Every table is:
  * ``bt_``-prefixed to namespace it away from the legacy schema,
  * chat-scoped (``chat_id`` in the key/index) so nothing leaks across groups,
  * created with ``IF NOT EXISTS`` and paired with a real ``downgrade`` — this
    migration is NON-destructive and reversible.

No data is read or written here; only DDL. Query paths use parameterized SQL and
open connections in WAL mode (set in ``blueteam.store``), not here.
"""

from .base import Migration


class BlueTeamMigration(Migration):
    version = "0003"
    description = "Blue Team Suite: link guard, scam/impersonation, join guard/anti-raid"
    destructive = False

    def upgrade(self, conn) -> None:
        c = conn.execute

        # ---- small key/value store (e.g. persisted challenge HMAC secret) ----
        c("""CREATE TABLE IF NOT EXISTS bt_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""")

        # ---- per-group, per-module policy -------------------------------
        c("""CREATE TABLE IF NOT EXISTS bt_group_policy (
            chat_id    INTEGER NOT NULL,
            module     TEXT    NOT NULL,           -- linkguard|scamguard|joinguard
            enabled    INTEGER NOT NULL DEFAULT 0,
            mode       TEXT    NOT NULL DEFAULT 'MONITOR',
            threshold  INTEGER NOT NULL DEFAULT 45,
            sensitivity TEXT   NOT NULL DEFAULT 'balanced',
            settings   TEXT,                       -- JSON: module-specific knobs
            updated_at INTEGER NOT NULL,
            updated_by INTEGER,
            PRIMARY KEY (chat_id, module)
        )""")

        # ---- per-group allow / deny lists -------------------------------
        c("""CREATE TABLE IF NOT EXISTS bt_listentry (
            chat_id    INTEGER NOT NULL,
            list_type  TEXT    NOT NULL,           -- allow|deny
            kind       TEXT    NOT NULL,           -- domain|url|user
            value      TEXT    NOT NULL,           -- normalized (etld1 / url key / user id)
            note       TEXT,
            added_by   INTEGER,
            added_at   INTEGER NOT NULL,
            PRIMARY KEY (chat_id, list_type, kind, value)
        )""")

        # ---- URL analysis cache + deferred deep-probe state -------------
        c("""CREATE TABLE IF NOT EXISTS bt_url_cache (
            url_key    TEXT PRIMARY KEY,           -- sha256 of canonical url
            chat_id    INTEGER,                    -- last chat that looked it up
            url        TEXT NOT NULL,
            score      INTEGER NOT NULL DEFAULT 0,
            verdict    TEXT NOT NULL DEFAULT 'SAFE',
            signals    TEXT,                       -- JSON list
            deep_state TEXT NOT NULL DEFAULT 'none', -- none|pending|done|error
            deep       TEXT,                       -- JSON deep-probe result
            first_seen INTEGER NOT NULL,
            last_seen  INTEGER NOT NULL,
            hits       INTEGER NOT NULL DEFAULT 1
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_url_cache_seen ON bt_url_cache(last_seen)")

        # ---- shared blocklist feed (URLhaus/OpenPhish etc.) -------------
        c("""CREATE TABLE IF NOT EXISTS bt_feed (
            source    TEXT NOT NULL,               -- urlhaus|openphish|...
            kind      TEXT NOT NULL,               -- host|url
            value     TEXT NOT NULL,
            added_at  INTEGER NOT NULL,
            PRIMARY KEY (source, value)
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_feed_value ON bt_feed(value)")

        # ---- module event log (for stats/history/dashboard) ------------
        c("""CREATE TABLE IF NOT EXISTS bt_event (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id   INTEGER NOT NULL,
            module    TEXT NOT NULL,
            user_id   INTEGER,
            subject   TEXT,                         -- url key / campaign id (non-sensitive)
            score     INTEGER,
            verdict   TEXT,
            action    TEXT,                         -- MONITOR|WARN|DELETE|...
            attack    TEXT,                         -- ATT&CK tags (comma-joined)
            created_at INTEGER NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_event_chat_time ON bt_event(chat_id, created_at)")
        c("CREATE INDEX IF NOT EXISTS ix_bt_event_module ON bt_event(chat_id, module, created_at)")

        # ---- admin review queue ----------------------------------------
        c("""CREATE TABLE IF NOT EXISTS bt_review (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id   INTEGER NOT NULL,
            module    TEXT NOT NULL,
            user_id   INTEGER,
            subject   TEXT,
            score     INTEGER,
            verdict   TEXT,
            reasons   TEXT,                         -- JSON top reasons
            status    TEXT NOT NULL DEFAULT 'OPEN', -- OPEN|NOT_SPAM|DELETED|MUTED|BANNED
            created_at INTEGER NOT NULL,
            decided_by INTEGER,
            decided_at INTEGER
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_review_open ON bt_review(chat_id, status, created_at)")

        # ---- VIP / protected identities (impersonation targets) --------
        c("""CREATE TABLE IF NOT EXISTS bt_vip (
            chat_id      INTEGER NOT NULL,
            user_id      INTEGER,
            username     TEXT,
            display_name TEXT,
            role         TEXT NOT NULL DEFAULT 'vip', -- admin|vip
            added_by     INTEGER,
            added_at     INTEGER NOT NULL,
            PRIMARY KEY (chat_id, user_id, username)
        )""")

        # ---- Join Guard: raid state (survives restart) -----------------
        c("""CREATE TABLE IF NOT EXISTS bt_raid_state (
            chat_id    INTEGER PRIMARY KEY,
            state      TEXT NOT NULL DEFAULT 'NORMAL', -- NORMAL|ELEVATED|RAID|COOLDOWN
            since      INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            meta       TEXT
        )""")

        # ---- Join Guard: permission snapshot for lockdown restore ------
        c("""CREATE TABLE IF NOT EXISTS bt_perm_snapshot (
            chat_id        INTEGER PRIMARY KEY,
            permissions    TEXT NOT NULL,           -- JSON of prior ChatPermissions
            taken_at       INTEGER NOT NULL,
            lockdown_until INTEGER,                  -- dead-man switch max end time
            active         INTEGER NOT NULL DEFAULT 1
        )""")

        # ---- Join Guard: pending challenges ----------------------------
        c("""CREATE TABLE IF NOT EXISTS bt_challenge (
            chat_id    INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            nonce      TEXT NOT NULL,
            answer     TEXT,
            expires_at INTEGER NOT NULL,
            attempts   INTEGER NOT NULL DEFAULT 0,
            status     TEXT NOT NULL DEFAULT 'PENDING', -- PENDING|PASSED|FAILED|EXPIRED
            created_at INTEGER NOT NULL,
            PRIMARY KEY (chat_id, user_id)
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_challenge_exp ON bt_challenge(status, expires_at)")

        # ---- Join Guard: bulk-action audit (for /raid undo) ------------
        c("""CREATE TABLE IF NOT EXISTS bt_raid_action (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id   INTEGER NOT NULL,
            raid_id   TEXT NOT NULL,                -- correlation id of the raid episode
            user_id   INTEGER NOT NULL,
            action    TEXT NOT NULL,                -- restricted|banned|kicked
            reversible INTEGER NOT NULL DEFAULT 1,
            undone    INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )""")
        c("CREATE INDEX IF NOT EXISTS ix_bt_raid_action ON bt_raid_action(chat_id, raid_id)")

    def downgrade(self, conn) -> None:
        for table in ("bt_meta", "bt_group_policy", "bt_listentry", "bt_url_cache",
                      "bt_feed", "bt_event", "bt_review", "bt_vip", "bt_raid_state",
                      "bt_perm_snapshot", "bt_challenge", "bt_raid_action"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
