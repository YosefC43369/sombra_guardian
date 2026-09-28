"""
blueteam/intel/adapters.py — SQLite adapter implementing the Intel repository ports.

All access is parameterized and scoped to the ``bt_``-prefixed tables from
migration 0004. WAL + a process-lock keep the shared connection safe; blocking
work is expected to run in an executor. Rows are mapped to/from the pure
:class:`blueteam.intel.domain.IOC`. Sightings carry ``chat_id`` so a caller can
scope reads to a tenant's groups.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from .domain import IOC, IOCType, TLP


def _row_to_ioc(r: sqlite3.Row) -> IOC:
    return IOC(
        ioc_type=IOCType.coerce(r["ioc_type"]),
        value=r["value"],
        sources=[s for s in (r["sources"] or "").split(",") if s],
        first_seen=r["first_seen"] or 0.0,
        last_seen=r["last_seen"] or 0.0,
        expires_at=r["expires_at"],
        confidence=r["confidence"] or 0,
        severity=r["severity"] or "medium",
        tlp=r["tlp"] or "amber",
        tags=[t for t in (r["tags"] or "").split(",") if t],
        attack=r["attack"] or "",
        family=r["family"] or "",
        provenance=_load_json(r["provenance"]),
        is_local=bool(r["is_local"]),
    )


def _load_json(s: Optional[str]) -> Dict[str, Any]:
    if not s:
        return {}
    try:
        d = json.loads(s)
        return d if isinstance(d, dict) else {}
    except (ValueError, TypeError):
        return {}


class SqliteIntelRepository:
    """Implements :class:`blueteam.intel.service.IocRepository`."""

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

    # ---------------- IOCs ----------------
    def upsert_iocs(self, iocs: List[IOC], now: float) -> int:
        if not iocs:
            return 0
        with self._lock:
            cur = self._conn
            ids = [i.id for i in iocs]
            existing: Dict[str, sqlite3.Row] = {}
            # chunk the IN() to stay under SQLite's variable limit
            for start in range(0, len(ids), 400):
                chunk = ids[start:start + 400]
                q = f"SELECT * FROM bt_ioc WHERE ioc_id IN ({','.join('?' * len(chunk))})"
                for r in cur.execute(q, tuple(chunk)):
                    existing[r["ioc_id"]] = r
            n = 0
            for ioc in iocs:
                prev = existing.get(ioc.id)
                if prev is not None:
                    srcs = sorted(set(
                        [s for s in (prev["sources"] or "").split(",") if s] + list(ioc.sources)))
                    cur.execute(
                        """UPDATE bt_ioc SET sources=?, last_seen=?,
                           expires_at=?, confidence=?, severity=?, tags=?,
                           family=?, provenance=?, is_local=?
                           WHERE ioc_id=?""",
                        (",".join(srcs), now,
                         _max_opt(prev["expires_at"], ioc.expires_at),
                         max(prev["confidence"] or 0, ioc.confidence),
                         ioc.severity or prev["severity"], ",".join(ioc.tags),
                         ioc.family or prev["family"],
                         json.dumps(ioc.provenance, ensure_ascii=False),
                         1 if (ioc.is_local or prev["is_local"]) else 0, ioc.id))
                else:
                    cur.execute(
                        """INSERT INTO bt_ioc (ioc_id, ioc_type, value, sources,
                           first_seen, last_seen, expires_at, confidence, severity,
                           tlp, tags, attack, family, provenance, is_local)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (ioc.id, ioc.ioc_type.value, ioc.value, ",".join(ioc.sources),
                         ioc.first_seen or now, ioc.last_seen or now, ioc.expires_at,
                         ioc.confidence, ioc.severity,
                         ioc.tlp.value if isinstance(ioc.tlp, TLP) else str(ioc.tlp),
                         ",".join(ioc.tags), ioc.attack, ioc.family,
                         json.dumps(ioc.provenance, ensure_ascii=False),
                         1 if ioc.is_local else 0))
                    n += 1
            self._conn.commit()
            return n

    def all_active_iocs(self, now: float) -> List[IOC]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM bt_ioc WHERE expires_at IS NULL OR expires_at > ?",
                (now,)).fetchall()
        return [_row_to_ioc(r) for r in rows]

    def get_ioc(self, the_id: str) -> Optional[IOC]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM bt_ioc WHERE ioc_id=?", (the_id,)).fetchone()
        return _row_to_ioc(r) if r else None

    def delete_ioc(self, the_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM bt_ioc WHERE ioc_id=?", (the_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def record_sighting(self, the_id: str, chat_id: Optional[int], user_id: Optional[int],
                        context: str, now: float) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_ioc_sighting (ioc_id, chat_id, user_id, context, seen_at)
                   VALUES (?,?,?,?,?)""", (the_id, chat_id, user_id, context[:200], now))
            self._conn.commit()

    def sightings_for(self, the_id: str, limit: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT chat_id, user_id, context, seen_at FROM bt_ioc_sighting
                   WHERE ioc_id=? ORDER BY seen_at DESC LIMIT ?""",
                (the_id, max(1, min(500, limit)))).fetchall()
        return [dict(r) for r in rows]

    # ---------------- whitelist ----------------
    def add_whitelist(self, value: str, added_by: Optional[int], now: float) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_intel_whitelist (value, added_by, added_at)
                   VALUES (?,?,?) ON CONFLICT(value) DO UPDATE SET added_by=excluded.added_by""",
                (value, added_by, now))
            self._conn.commit()

    def remove_whitelist(self, value: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM bt_intel_whitelist WHERE value=?", (value,))
            self._conn.commit()
            return cur.rowcount > 0

    def list_whitelist(self) -> List[str]:
        with self._lock:
            return [r["value"] for r in self._conn.execute(
                "SELECT value FROM bt_intel_whitelist ORDER BY value").fetchall()]

    # ---------------- feed state ----------------
    def get_feed_state(self, feed: str) -> Dict[str, Any]:
        with self._lock:
            r = self._conn.execute("SELECT * FROM bt_feed_state WHERE feed=?", (feed,)).fetchone()
        return dict(r) if r else {}

    def save_feed_state(self, feed: str, state: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_feed_state
                   (feed, url, etag, last_modified, last_sync, last_status, item_count,
                    circuit_state, failures, enabled)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(feed) DO UPDATE SET
                     url=excluded.url, etag=excluded.etag,
                     last_modified=excluded.last_modified, last_sync=excluded.last_sync,
                     last_status=excluded.last_status, item_count=excluded.item_count,
                     circuit_state=excluded.circuit_state, failures=excluded.failures""",
                (feed, state.get("url", ""), state.get("etag", ""),
                 state.get("last_modified", ""), state.get("last_sync"),
                 state.get("last_status", ""), int(state.get("item_count", 0) or 0),
                 state.get("circuit_state", "closed"), int(state.get("failures", 0) or 0),
                 int(state.get("enabled", 1)) if state.get("enabled") is not None else 1))
            self._conn.commit()

    def set_feed_enabled(self, feed: str, enabled: bool) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO bt_feed_state (feed, enabled, item_count, failures)
                   VALUES (?,?,0,0)
                   ON CONFLICT(feed) DO UPDATE SET enabled=excluded.enabled""",
                (feed, 1 if enabled else 0))
            self._conn.commit()

    def list_feed_states(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(
                "SELECT * FROM bt_feed_state").fetchall()]

    # ---------------- stats ----------------
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM bt_ioc").fetchone()[0]
            by_type = {r[0]: r[1] for r in self._conn.execute(
                "SELECT ioc_type, COUNT(*) FROM bt_ioc GROUP BY ioc_type").fetchall()}
            local = self._conn.execute(
                "SELECT COUNT(*) FROM bt_ioc WHERE is_local=1").fetchone()[0]
            sightings = self._conn.execute("SELECT COUNT(*) FROM bt_ioc_sighting").fetchone()[0]
        return {"total": total, "by_type": by_type, "local": local, "sightings": sightings}


def _max_opt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


__all__ = ["SqliteIntelRepository"]
