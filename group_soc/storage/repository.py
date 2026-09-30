"""
group_soc/storage/repository.py — the storage base for every SOC store.

Follows the repo's established pattern (member_incident.py, plugins/manager.py):
open a short-lived sqlite3 connection per operation, ``sqlite3.Row`` factory, WAL
mode for concurrent readers. Schema is owned by migration 0006, never created here.

Every store subclasses :class:`SocStore` for the connection helpers, the shared
audit-log writer, per-group policy access, and retention cleanup.

All SQL is parameterized. No f-string values ever reach a query. Reads are bounded
(callers pass a limit clamped by ``util.bounded_limit``); no unbounded ``SELECT *``
scans on the event tables.
"""

from __future__ import annotations

import sqlite3
import logging
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

from ..util import now, json_dump, json_load
from ..exceptions import SocStorageError

logger = logging.getLogger("modbot.group_soc.storage")


class SocStore:
    def __init__(self, db_path: str = "bot.db"):
        self.db_path = db_path

    # ---- connection ----
    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise SocStorageError(str(exc), code="SOC_STORAGE_ERROR") from exc
        finally:
            conn.close()

    # ---- generic helpers ----
    def _insert(self, table: str, row: Dict[str, Any], *, replace: bool = False) -> None:
        cols = list(row.keys())
        placeholders = ", ".join("?" for _ in cols)
        verb = "INSERT OR REPLACE" if replace else "INSERT"
        sql = f"{verb} INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"
        with self._conn() as conn:
            conn.execute(sql, [row[c] for c in cols])

    def _update(self, table: str, key_col: str, key_val: Any,
                changes: Dict[str, Any]) -> int:
        if not changes:
            return 0
        sets = ", ".join(f"{c}=?" for c in changes)
        sql = f"UPDATE {table} SET {sets} WHERE {key_col}=?"
        with self._conn() as conn:
            cur = conn.execute(sql, list(changes.values()) + [key_val])
            return cur.rowcount

    def _get_one(self, sql: str, params: Iterable[Any]) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(sql, list(params)).fetchone()
            return dict(row) if row is not None else None

    def _get_many(self, sql: str, params: Iterable[Any]) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(sql, list(params)).fetchall()]

    def _count(self, sql: str, params: Iterable[Any]) -> int:
        with self._conn() as conn:
            row = conn.execute(sql, list(params)).fetchone()
            return int(row[0]) if row else 0

    # ---- audit (shared by all stores) ----
    def audit(self, chat_id: int, action: str, *, actor_hash: Optional[str] = None,
              target_kind: Optional[str] = None, target_id: Optional[str] = None,
              detail: Optional[dict] = None) -> None:
        """Append an audit row. Never raises into the caller — an audit failure
        must not abort the operation being audited."""
        try:
            self._insert("soc_audit_log", {
                "chat_id": int(chat_id or 0), "ts": now(), "actor_hash": actor_hash,
                "action": action, "target_kind": target_kind, "target_id": target_id,
                "detail": json_dump(detail),
            })
        except Exception:
            logger.debug("soc audit write failed for %s", action, exc_info=True)

    def list_audit(self, chat_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._get_many(
            "SELECT * FROM soc_audit_log WHERE chat_id=? ORDER BY ts DESC LIMIT ?",
            (int(chat_id or 0), int(limit)))
        for r in rows:
            r["detail"] = json_load(r.get("detail"))
        return rows

    # ---- per-group policy ----
    def get_policy(self, chat_id: int) -> Dict[str, Any]:
        row = self._get_one("SELECT * FROM soc_group_policy WHERE chat_id=?",
                            (int(chat_id or 0),))
        if row is None:
            return {"chat_id": int(chat_id or 0), "enabled": 0, "mode": "monitor",
                    "settings": {}}
        row["settings"] = json_load(row.get("settings"))
        return row

    def set_policy(self, chat_id: int, *, enabled: Optional[bool] = None,
                   mode: Optional[str] = None, settings: Optional[dict] = None,
                   updated_by: Optional[int] = None) -> Dict[str, Any]:
        current = self.get_policy(chat_id)
        new_enabled = current["enabled"] if enabled is None else (1 if enabled else 0)
        new_mode = mode or current.get("mode", "monitor")
        new_settings = settings if settings is not None else current.get("settings", {})
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO soc_group_policy (chat_id, enabled, mode, settings, updated_at, updated_by)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(chat_id) DO UPDATE SET
                     enabled=excluded.enabled, mode=excluded.mode,
                     settings=excluded.settings, updated_at=excluded.updated_at,
                     updated_by=excluded.updated_by""",
                (int(chat_id or 0), new_enabled, new_mode, json_dump(new_settings),
                 now(), updated_by))
        return self.get_policy(chat_id)

    def is_group_active(self, chat_id: int) -> bool:
        return bool(self.get_policy(chat_id).get("enabled"))

    # ---- retention ----
    def purge_older_than(self, table: str, ts_col: str, cutoff_ts: int) -> int:
        """Delete rows older than cutoff. Returns rows removed. Table/col names are
        validated against an allow-list so this can never be injected."""
        allowed = {
            "soc_events": "ts", "soc_signals": "ts", "soc_timeline": "ts",
            "soc_audit_log": "ts",
        }
        if table not in allowed or allowed[table] != ts_col:
            raise SocStorageError("retention on non-allowlisted table",
                                  code="SOC_STORAGE_ERROR", table=table)
        with self._conn() as conn:
            cur = conn.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (int(cutoff_ts),))
            return cur.rowcount
