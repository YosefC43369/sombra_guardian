"""
blueteam/dac/adapters.py — SQLite adapter implementing the DaC rule repository.

Parameterized access to the ``bt_rule`` / ``bt_rule_version`` / ``bt_rule_hit``
tables from migration 0004. ``canary_chats`` and ``tags`` are stored as JSON text.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional


def _loads(s: Optional[str], default):
    if not s:
        return default
    try:
        return json.loads(s)
    except (ValueError, TypeError):
        return default


class SqliteRuleRepository:
    def __init__(self, db_path: str = "bot.db", conn: Optional[sqlite3.Connection] = None):
        self._lock = threading.RLock()
        if conn is not None:
            self._conn = conn
        else:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self._conn.execute("PRAGMA busy_timeout=5000")
            except sqlite3.Error:
                pass

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def _rule_row(self, r: sqlite3.Row) -> Dict[str, Any]:
        return {"rule_id": r["rule_id"], "title": r["title"], "status": r["status"],
                "level": r["level"], "logsource": r["logsource"], "version": r["version"],
                "state": r["state"], "canary_chats": _loads(r["canary_chats"], []),
                "tags": _loads(r["tags"], []), "cooldown_s": r["cooldown_s"],
                "dedupe_field": r["dedupe_field"], "updated_at": r["updated_at"],
                "updated_by": r["updated_by"]}

    def list_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM bt_rule ORDER BY rule_id").fetchall()
        return [self._rule_row(r) for r in rows]

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM bt_rule WHERE rule_id=?", (rule_id,)).fetchone()
        return self._rule_row(r) if r else None

    def upsert_rule(self, rec: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_rule (rule_id, title, status, level, logsource, version,
                   state, canary_chats, tags, cooldown_s, dedupe_field, updated_at, updated_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(rule_id) DO UPDATE SET
                     title=excluded.title, level=excluded.level, logsource=excluded.logsource,
                     version=excluded.version, state=excluded.state,
                     canary_chats=excluded.canary_chats, tags=excluded.tags,
                     cooldown_s=excluded.cooldown_s, dedupe_field=excluded.dedupe_field,
                     updated_at=excluded.updated_at, updated_by=excluded.updated_by""",
                (rec["rule_id"], rec.get("title", ""), rec.get("status", "experimental"),
                 rec.get("level", "medium"), rec.get("logsource", "message"),
                 rec.get("version", "1.0.0"), rec.get("state", "disabled"),
                 json.dumps(rec.get("canary_chats", [])), json.dumps(rec.get("tags", [])),
                 int(rec.get("cooldown_s", 0) or 0), rec.get("dedupe_field", ""),
                 rec.get("updated_at", 0.0), rec.get("updated_by")))
            self._conn.commit()

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM bt_rule WHERE rule_id=?", (rule_id,))
            self._conn.execute("DELETE FROM bt_rule_version WHERE rule_id=?", (rule_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def set_state(self, rule_id: str, state: str, canary_chats: List[int],
                  updated_by: Optional[int], now: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE bt_rule SET state=?, canary_chats=?, updated_at=?, updated_by=? WHERE rule_id=?",
                (state, json.dumps(list(canary_chats or [])), now, updated_by, rule_id))
            self._conn.commit()

    def add_version(self, rule_id: str, version: str, body: str, sha256: str,
                    author: Optional[int], notes: str, now: float) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_rule_version (rule_id, version, body, sha256, author, created_at, notes)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(rule_id, version) DO UPDATE SET
                     body=excluded.body, sha256=excluded.sha256, notes=excluded.notes""",
                (rule_id, version, body, sha256, author, now, notes))
            self._conn.commit()

    def list_versions(self, rule_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM bt_rule_version WHERE rule_id=? ORDER BY created_at, version",
                (rule_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_version(self, rule_id: str, version: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM bt_rule_version WHERE rule_id=? AND version=?",
                (rule_id, version)).fetchone()
        return dict(r) if r else None

    def latest_version_hash(self, rule_id: str) -> str:
        versions = self.list_versions(rule_id)
        return versions[-1]["sha256"] if versions else ""

    def record_hit(self, rule_id: str, chat_id: Optional[int], user_id: Optional[int],
                   mode: str, now: float) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_rule_hit (rule_id, chat_id, user_id, mode, matched_at)
                   VALUES (?,?,?,?,?)""", (rule_id, chat_id, user_id, mode, now))
            self._conn.commit()

    def recent_hits(self, rule_id: str, limit: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM bt_rule_hit WHERE rule_id=? ORDER BY matched_at DESC LIMIT ?",
                (rule_id, max(1, min(500, limit)))).fetchall()
        return [dict(r) for r in rows]

    def hit_stats(self, since: float) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT rule_id, COUNT(*) FROM bt_rule_hit WHERE matched_at >= ? GROUP BY rule_id",
                (since,)).fetchall()
        return {r[0]: r[1] for r in rows}


__all__ = ["SqliteRuleRepository"]
