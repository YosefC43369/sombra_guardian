"""
blueteam/posture/adapters.py — SQLite adapter for the Posture repository.

Parameterized access to ``bt_posture_snapshot`` / ``bt_posture_rollup`` /
``bt_report`` / ``bt_tenant`` (migration 0004). Rollups keep a running mean per
(chat, metric, hour) so trend never rescans raw events.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Any, Dict, List, Optional


class SqlitePostureRepository:
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

    def save_snapshot(self, snapshot_id, tenant_id, chat_id, score, grade, coverage,
                      breakdown, now) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_posture_snapshot
                   (snapshot_id, tenant_id, chat_id, score, grade, coverage, breakdown, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (snapshot_id, tenant_id, chat_id, score, grade, coverage, breakdown, now))
            self._conn.commit()

    def latest_snapshot(self, chat_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM bt_posture_snapshot WHERE chat_id=? ORDER BY created_at DESC LIMIT 1",
                (chat_id,)).fetchone()
        return dict(r) if r else None

    def snapshots(self, chat_id: int, limit: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM bt_posture_snapshot WHERE chat_id=? ORDER BY created_at DESC LIMIT ?",
                (chat_id, max(1, min(500, limit)))).fetchall()
        return [dict(r) for r in rows]

    def add_rollup(self, chat_id: int, metric: str, hour: int, value: float) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value, count FROM bt_posture_rollup WHERE chat_id=? AND metric=? AND hour=?",
                (chat_id, metric, hour)).fetchone()
            if row is None:
                self._conn.execute(
                    """INSERT INTO bt_posture_rollup (chat_id, metric, hour, value, count)
                       VALUES (?,?,?,?,1)""", (chat_id, metric, hour, value))
            else:
                cnt = row["count"] + 1
                mean = (row["value"] * row["count"] + value) / cnt
                self._conn.execute(
                    "UPDATE bt_posture_rollup SET value=?, count=? WHERE chat_id=? AND metric=? AND hour=?",
                    (mean, cnt, chat_id, metric, hour))
            self._conn.commit()

    def rollups(self, chat_id: int, metric: str, since_hour: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT hour, value, count FROM bt_posture_rollup
                   WHERE chat_id=? AND metric=? AND hour>=? ORDER BY hour""",
                (chat_id, metric, since_hour)).fetchall()
        return [dict(r) for r in rows]

    def save_report(self, report_id, tenant_id, chat_id, profile, fmt, sha256, now) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_report (report_id, tenant_id, chat_id, profile, fmt, sha256, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (report_id, tenant_id, chat_id, profile, fmt, sha256, now))
            self._conn.commit()

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM bt_report WHERE report_id=?", (report_id,)).fetchone()
        return dict(r) if r else None

    def get_branding(self, tenant_id: str) -> Dict[str, Any]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM bt_tenant WHERE tenant_id=?", (tenant_id,)).fetchone()
        return dict(r) if r else {}

    def set_branding(self, tenant_id: str, fields: Dict[str, Any]) -> None:
        allowed = {k: v for k, v in fields.items()
                   if k in ("name", "brand_name", "brand_color", "brand_footer")}
        with self._lock:
            exists = self._conn.execute(
                "SELECT 1 FROM bt_tenant WHERE tenant_id=?", (tenant_id,)).fetchone()
            if exists is None:
                import time as _t
                self._conn.execute(
                    """INSERT INTO bt_tenant (tenant_id, name, brand_name, brand_color, brand_footer, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (tenant_id, allowed.get("name", ""), allowed.get("brand_name", ""),
                     allowed.get("brand_color", "#0b3d5c"), allowed.get("brand_footer", ""), _t.time()))
            elif allowed:
                sets = ", ".join(f"{k}=?" for k in allowed)
                self._conn.execute(f"UPDATE bt_tenant SET {sets} WHERE tenant_id=?",
                                   (*allowed.values(), tenant_id))
            self._conn.commit()


__all__ = ["SqlitePostureRepository"]
