"""
blueteam/store.py — the SQLite persistence layer for the Blue Team Suite.

One small, focused data-access object over the ``bt_*`` tables created by
migration 0003. Design points from the task:

  * **WAL** journal mode + sensible indexes (created in the migration) for
    concurrent reads while the bot writes.
  * **Parameterized** queries everywhere — no string-built SQL, ever.
  * **Chat-scoped**: every method that stores group data takes ``chat_id`` and
    filters on it, so nothing leaks across groups.
  * **Reused connection** with a lock (the bot is single-loop asyncio, but blocking
    DB work runs in a thread executor, so a lock keeps the shared connection safe).
  * **Retention**: :meth:`cleanup` drops rows past the configured age.

Only DDL lives in the migration; every read/write path is here.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.blueteam.store")


def _now() -> int:
    return int(time.time())


class BlueTeamStore:
    def __init__(self, db_path: str = "bot.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
        except sqlite3.Error:
            logger.debug("BLUETEAM STORE | PRAGMA setup skipped", exc_info=True)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    # ---- low-level helpers ----------------------------------------------
    def _exec(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def _query(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def _one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        rows = self._query(sql, params)
        return rows[0] if rows else None

    # ---- meta (key/value; HMAC secret persistence) ----------------------
    def get_meta(self, key: str) -> Optional[str]:
        row = self._one("SELECT value FROM bt_meta WHERE key=?", (key,))
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self._exec("INSERT INTO bt_meta(key,value) VALUES(?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def get_or_create_secret(self, key: str = "hmac_secret") -> str:
        """Return a stable per-database secret, generating one on first use.
        Used to sign challenge callbacks when no env secret is configured."""
        existing = self.get_meta(key)
        if existing:
            return existing
        secret = secrets.token_hex(32)
        self.set_meta(key, secret)
        return secret

    # ---- per-group policy -----------------------------------------------
    def get_policy(self, chat_id: int, module: str) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT * FROM bt_group_policy WHERE chat_id=? AND module=?",
                        (chat_id, module))
        if not row:
            return None
        d = dict(row)
        d["settings"] = json.loads(d["settings"]) if d.get("settings") else {}
        return d

    def set_policy(self, chat_id: int, module: str, *, enabled: Optional[bool] = None,
                   mode: Optional[str] = None, threshold: Optional[int] = None,
                   sensitivity: Optional[str] = None,
                   settings: Optional[dict] = None, actor: Optional[int] = None) -> None:
        cur = self.get_policy(chat_id, module) or {
            "enabled": 0, "mode": "MONITOR", "threshold": 45,
            "sensitivity": "balanced", "settings": {}}
        merged_settings = dict(cur.get("settings") or {})
        if settings:
            merged_settings.update(settings)
        self._exec(
            """INSERT INTO bt_group_policy
                 (chat_id, module, enabled, mode, threshold, sensitivity, settings,
                  updated_at, updated_by)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(chat_id, module) DO UPDATE SET
                 enabled=excluded.enabled, mode=excluded.mode,
                 threshold=excluded.threshold, sensitivity=excluded.sensitivity,
                 settings=excluded.settings, updated_at=excluded.updated_at,
                 updated_by=excluded.updated_by""",
            (chat_id, module,
             int(cur["enabled"] if enabled is None else bool(enabled)),
             mode if mode is not None else cur["mode"],
             int(threshold if threshold is not None else cur["threshold"]),
             sensitivity if sensitivity is not None else cur["sensitivity"],
             json.dumps(merged_settings, ensure_ascii=False), _now(), actor))

    # ---- allow / deny lists ---------------------------------------------
    def add_list_entry(self, chat_id: int, list_type: str, kind: str, value: str,
                       note: str = "", actor: Optional[int] = None) -> None:
        self._exec(
            """INSERT INTO bt_listentry
                 (chat_id, list_type, kind, value, note, added_by, added_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(chat_id, list_type, kind, value) DO UPDATE SET
                 note=excluded.note, added_by=excluded.added_by,
                 added_at=excluded.added_at""",
            (chat_id, list_type, kind, value, note, actor, _now()))

    def remove_list_entry(self, chat_id: int, list_type: str, kind: str,
                          value: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM bt_listentry WHERE chat_id=? AND list_type=? "
                "AND kind=? AND value=?", (chat_id, list_type, kind, value))
            self._conn.commit()
            return cur.rowcount > 0

    def in_list(self, chat_id: int, list_type: str, kind: str, value: str) -> bool:
        return self._one(
            "SELECT 1 FROM bt_listentry WHERE chat_id=? AND list_type=? "
            "AND kind=? AND value=?", (chat_id, list_type, kind, value)) is not None

    def list_entries(self, chat_id: int, list_type: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT * FROM bt_listentry WHERE chat_id=? AND list_type=? "
            "ORDER BY added_at DESC", (chat_id, list_type))]

    # ---- URL cache -------------------------------------------------------
    def get_url_cache(self, url_key: str) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT * FROM bt_url_cache WHERE url_key=?", (url_key,))
        if not row:
            return None
        d = dict(row)
        d["signals"] = json.loads(d["signals"]) if d.get("signals") else []
        d["deep"] = json.loads(d["deep"]) if d.get("deep") else None
        return d

    def upsert_url_cache(self, url_key: str, url: str, score: int, verdict: str,
                         signals: list, chat_id: Optional[int] = None,
                         deep_state: str = "none") -> None:
        now = _now()
        self._exec(
            """INSERT INTO bt_url_cache
                 (url_key, chat_id, url, score, verdict, signals, deep_state,
                  first_seen, last_seen, hits)
               VALUES (?,?,?,?,?,?,?,?,?,1)
               ON CONFLICT(url_key) DO UPDATE SET
                 score=excluded.score, verdict=excluded.verdict,
                 signals=excluded.signals, last_seen=excluded.last_seen,
                 hits=bt_url_cache.hits+1""",
            (url_key, chat_id, url, score, verdict,
             json.dumps(signals, ensure_ascii=False), deep_state, now, now))

    def set_url_deep(self, url_key: str, deep_state: str, deep: Optional[dict],
                     score: Optional[int] = None, verdict: Optional[str] = None) -> None:
        sets = ["deep_state=?", "deep=?", "last_seen=?"]
        params: List[Any] = [deep_state,
                             json.dumps(deep, ensure_ascii=False) if deep else None,
                             _now()]
        if score is not None:
            sets.append("score=?"); params.append(score)
        if verdict is not None:
            sets.append("verdict=?"); params.append(verdict)
        params.append(url_key)
        self._exec(f"UPDATE bt_url_cache SET {', '.join(sets)} WHERE url_key=?",
                   tuple(params))

    # ---- blocklist feed --------------------------------------------------
    def feed_add_many(self, source: str, kind: str, values: List[str]) -> int:
        now = _now()
        rows = [(source, kind, v, now) for v in values if v]
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                "INSERT OR IGNORE INTO bt_feed(source, kind, value, added_at) "
                "VALUES (?,?,?,?)", rows)
            self._conn.commit()
        return len(rows)

    def feed_contains(self, value: str) -> Optional[str]:
        row = self._one("SELECT source FROM bt_feed WHERE value=? LIMIT 1", (value,))
        return row["source"] if row else None

    def feed_count(self) -> int:
        row = self._one("SELECT COUNT(*) AS n FROM bt_feed")
        return row["n"] if row else 0

    # ---- event log + stats ----------------------------------------------
    def log_event(self, chat_id: int, module: str, *, user_id: Optional[int] = None,
                  subject: str = "", score: Optional[int] = None, verdict: str = "",
                  action: str = "", attack: str = "") -> None:
        self._exec(
            """INSERT INTO bt_event
                 (chat_id, module, user_id, subject, score, verdict, action, attack,
                  created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (chat_id, module, user_id, subject, score, verdict, action, attack, _now()))

    def stats(self, chat_id: int, since_seconds: int) -> Dict[str, Any]:
        cutoff = _now() - since_seconds
        rows = self._query(
            "SELECT module, verdict, action, COUNT(*) AS n FROM bt_event "
            "WHERE chat_id=? AND created_at>=? GROUP BY module, verdict, action",
            (chat_id, cutoff))
        out: Dict[str, Any] = {"by_module": {}, "by_action": {}, "total": 0}
        for r in rows:
            n = r["n"]
            out["total"] += n
            out["by_module"][r["module"]] = out["by_module"].get(r["module"], 0) + n
            if r["action"]:
                out["by_action"][r["action"]] = out["by_action"].get(r["action"], 0) + n
        return out

    def recent_events(self, chat_id: int, module: Optional[str] = None,
                      limit: int = 20) -> List[Dict[str, Any]]:
        if module:
            rows = self._query(
                "SELECT * FROM bt_event WHERE chat_id=? AND module=? "
                "ORDER BY created_at DESC LIMIT ?", (chat_id, module, int(limit)))
        else:
            rows = self._query(
                "SELECT * FROM bt_event WHERE chat_id=? ORDER BY created_at DESC "
                "LIMIT ?", (chat_id, int(limit)))
        return [dict(r) for r in rows]

    # ---- review queue ----------------------------------------------------
    def add_review(self, chat_id: int, module: str, user_id: Optional[int],
                   subject: str, score: int, verdict: str, reasons: list) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO bt_review
                     (chat_id, module, user_id, subject, score, verdict, reasons,
                      status, created_at)
                   VALUES (?,?,?,?,?,?,?, 'OPEN', ?)""",
                (chat_id, module, user_id, subject, score, verdict,
                 json.dumps(reasons, ensure_ascii=False), _now()))
            self._conn.commit()
            return cur.lastrowid

    def list_reviews(self, chat_id: int, status: str = "OPEN",
                     limit: int = 20) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT * FROM bt_review WHERE chat_id=? AND status=? "
            "ORDER BY created_at DESC LIMIT ?", (chat_id, status, int(limit)))]

    def decide_review(self, review_id: int, chat_id: int, status: str,
                      decided_by: Optional[int]) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE bt_review SET status=?, decided_by=?, decided_at=? "
                "WHERE id=? AND chat_id=? AND status='OPEN'",
                (status, decided_by, _now(), review_id, chat_id))
            self._conn.commit()
            return cur.rowcount > 0

    # ---- VIP / protected identities -------------------------------------
    def add_vip(self, chat_id: int, *, user_id: Optional[int] = None,
                username: str = "", display_name: str = "", role: str = "vip",
                actor: Optional[int] = None) -> None:
        self._exec(
            """INSERT INTO bt_vip
                 (chat_id, user_id, username, display_name, role, added_by, added_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(chat_id, user_id, username) DO UPDATE SET
                 display_name=excluded.display_name, role=excluded.role""",
            (chat_id, user_id or 0, (username or "").lstrip("@").lower(),
             display_name, role, actor, _now()))

    def list_vips(self, chat_id: int) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT * FROM bt_vip WHERE chat_id=? ORDER BY role, added_at",
            (chat_id,))]

    def remove_vip(self, chat_id: int, user_id: Optional[int] = None,
                   username: str = "") -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM bt_vip WHERE chat_id=? AND (user_id=? OR username=?)",
                (chat_id, user_id or 0, (username or "").lstrip("@").lower()))
            self._conn.commit()
            return cur.rowcount > 0

    # ---- raid state ------------------------------------------------------
    def get_raid_state(self, chat_id: int) -> Dict[str, Any]:
        row = self._one("SELECT * FROM bt_raid_state WHERE chat_id=?", (chat_id,))
        if not row:
            return {"chat_id": chat_id, "state": "NORMAL", "since": 0,
                    "updated_at": 0, "meta": {}}
        d = dict(row)
        d["meta"] = json.loads(d["meta"]) if d.get("meta") else {}
        return d

    def set_raid_state(self, chat_id: int, state: str, meta: Optional[dict] = None,
                       since: Optional[int] = None) -> None:
        now = _now()
        cur = self.get_raid_state(chat_id)
        since_val = since if since is not None else (
            cur["since"] if cur["state"] == state and cur["since"] else now)
        self._exec(
            """INSERT INTO bt_raid_state (chat_id, state, since, updated_at, meta)
               VALUES (?,?,?,?,?)
               ON CONFLICT(chat_id) DO UPDATE SET
                 state=excluded.state, since=excluded.since,
                 updated_at=excluded.updated_at, meta=excluded.meta""",
            (chat_id, state, since_val, now,
             json.dumps(meta or {}, ensure_ascii=False)))

    # ---- permission snapshot (lockdown restore) -------------------------
    def save_perm_snapshot(self, chat_id: int, permissions: dict,
                           lockdown_until: Optional[int]) -> None:
        self._exec(
            """INSERT INTO bt_perm_snapshot
                 (chat_id, permissions, taken_at, lockdown_until, active)
               VALUES (?,?,?,?,1)
               ON CONFLICT(chat_id) DO UPDATE SET
                 permissions=excluded.permissions, taken_at=excluded.taken_at,
                 lockdown_until=excluded.lockdown_until, active=1""",
            (chat_id, json.dumps(permissions, ensure_ascii=False), _now(),
             lockdown_until))

    def get_perm_snapshot(self, chat_id: int) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT * FROM bt_perm_snapshot WHERE chat_id=? AND active=1",
                        (chat_id,))
        if not row:
            return None
        d = dict(row)
        d["permissions"] = json.loads(d["permissions"]) if d.get("permissions") else {}
        return d

    def clear_perm_snapshot(self, chat_id: int) -> None:
        self._exec("UPDATE bt_perm_snapshot SET active=0 WHERE chat_id=?", (chat_id,))

    def active_lockdowns(self) -> List[Dict[str, Any]]:
        """All active lockdown snapshots — used by the dead-man switch at startup."""
        rows = self._query("SELECT * FROM bt_perm_snapshot WHERE active=1")
        out = []
        for r in rows:
            d = dict(r)
            d["permissions"] = json.loads(d["permissions"]) if d.get("permissions") else {}
            out.append(d)
        return out

    # ---- challenges ------------------------------------------------------
    def create_challenge(self, chat_id: int, user_id: int, nonce: str, answer: str,
                         ttl_seconds: int) -> None:
        now = _now()
        self._exec(
            """INSERT INTO bt_challenge
                 (chat_id, user_id, nonce, answer, expires_at, attempts, status,
                  created_at)
               VALUES (?,?,?,?,?,0,'PENDING',?)
               ON CONFLICT(chat_id, user_id) DO UPDATE SET
                 nonce=excluded.nonce, answer=excluded.answer,
                 expires_at=excluded.expires_at, attempts=0, status='PENDING',
                 created_at=excluded.created_at""",
            (chat_id, user_id, nonce, answer, now + ttl_seconds, now))

    def get_challenge(self, chat_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT * FROM bt_challenge WHERE chat_id=? AND user_id=?",
                        (chat_id, user_id))
        return dict(row) if row else None

    def bump_challenge_attempt(self, chat_id: int, user_id: int) -> int:
        with self._lock:
            self._conn.execute(
                "UPDATE bt_challenge SET attempts=attempts+1 "
                "WHERE chat_id=? AND user_id=?", (chat_id, user_id))
            self._conn.commit()
        row = self.get_challenge(chat_id, user_id)
        return row["attempts"] if row else 0

    def set_challenge_status(self, chat_id: int, user_id: int, status: str) -> None:
        self._exec("UPDATE bt_challenge SET status=? WHERE chat_id=? AND user_id=?",
                   (status, chat_id, user_id))

    def due_challenges(self, now: Optional[int] = None) -> List[Dict[str, Any]]:
        cutoff = now if now is not None else _now()
        return [dict(r) for r in self._query(
            "SELECT * FROM bt_challenge WHERE status='PENDING' AND expires_at<=?",
            (cutoff,))]

    # ---- raid actions (undo) --------------------------------------------
    def log_raid_action(self, chat_id: int, raid_id: str, user_id: int,
                        action: str, reversible: bool = True) -> None:
        self._exec(
            """INSERT INTO bt_raid_action
                 (chat_id, raid_id, user_id, action, reversible, undone, created_at)
               VALUES (?,?,?,?,?,0,?)""",
            (chat_id, raid_id, user_id, action, int(reversible), _now()))

    def list_raid_actions(self, chat_id: int, raid_id: Optional[str] = None,
                          only_reversible: bool = True) -> List[Dict[str, Any]]:
        sql = ("SELECT * FROM bt_raid_action WHERE chat_id=? AND undone=0"
               + (" AND reversible=1" if only_reversible else ""))
        params: List[Any] = [chat_id]
        if raid_id:
            sql += " AND raid_id=?"
            params.append(raid_id)
        sql += " ORDER BY created_at DESC"
        return [dict(r) for r in self._query(sql, tuple(params))]

    def mark_raid_action_undone(self, action_id: int) -> None:
        self._exec("UPDATE bt_raid_action SET undone=1 WHERE id=?", (action_id,))

    def latest_raid_id(self, chat_id: int) -> Optional[str]:
        row = self._one(
            "SELECT raid_id FROM bt_raid_action WHERE chat_id=? "
            "ORDER BY created_at DESC LIMIT 1", (chat_id,))
        return row["raid_id"] if row else None

    # ---- retention -------------------------------------------------------
    def cleanup(self, retention_days: int) -> Dict[str, int]:
        cutoff = _now() - retention_days * 86400
        removed: Dict[str, int] = {}
        with self._lock:
            for table, col, extra in (
                ("bt_event", "created_at", ""),
                ("bt_url_cache", "last_seen", ""),
                ("bt_review", "created_at", " AND status!='OPEN'"),
                ("bt_challenge", "created_at", " AND status!='PENDING'"),
                ("bt_raid_action", "created_at", ""),
            ):
                cur = self._conn.execute(
                    f"DELETE FROM {table} WHERE {col}<?{extra}", (cutoff,))
                removed[table] = cur.rowcount
            self._conn.commit()
        return removed

    def purge_user(self, chat_id: int, user_id: int) -> Dict[str, int]:
        """Delete a user's Blue Team rows in a chat (supports /memberpurge)."""
        removed: Dict[str, int] = {}
        with self._lock:
            for table in ("bt_event", "bt_review", "bt_challenge", "bt_raid_action",
                          "bt_vip"):
                cur = self._conn.execute(
                    f"DELETE FROM {table} WHERE chat_id=? AND user_id=?",
                    (chat_id, user_id))
                removed[table] = cur.rowcount
            self._conn.commit()
        return removed
