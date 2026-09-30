"""
cve_tracker.storage.repository — typed CRUD + queries over the cve_ tables.

The repository is the only module that touches sqlite for CVE data. It speaks in
domain models (:class:`CVERecord`, :class:`Subscription`, …), keeps the indexed
child tables (references/products/cwes) in sync with the JSON blob on every
save, and exposes query methods that lean on the indexes rather than scanning
(rules §19, §47, §51).

Concurrency: each public method opens a short-lived connection (the news.py
pattern) so the background loop, the command handlers and the alert dispatcher
never share a cursor. Writes that touch several tables run in one transaction.
A transient 'database is locked' is retried a few times with a short sleep.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from ..enums import Severity
from ..models import (
    CVERecord,
    Subscription,
    Notification,
    SourceState,
    AISummary,
)
from ..utils import now_epoch, slugify
from .database import connect, ensure_schema

logger = logging.getLogger("modbot.cve.repository")

_RETRYABLE = ("database is locked", "database is busy")


def _content_hash(rec: CVERecord) -> str:
    """Stable hash of the fields whose change is worth detecting/notifying.
    Deliberately excludes volatile fields (fetched_at, enriched_at)."""
    payload = {
        "desc": rec.description or "",
        "cvss": rec.cvss_score,
        "cvss_v": rec.cvss_version,
        "sev": rec.severity,
        "kev": rec.in_kev,
        "maturity": rec.exploit_maturity,
        "cwes": sorted(rec.cwe_ids),
        "refs": sorted(r.url for r in rec.references),
        "products": sorted(p.key for p in rec.products),
        "title": rec.title or "",
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class CVERepository:
    def __init__(self, db_path: str = "bot.db"):
        self.db_path = db_path

    # ---------------- connection ----------------

    def _conn(self) -> sqlite3.Connection:
        return connect(self.db_path)

    def init_schema(self) -> None:
        conn = self._conn()
        try:
            ensure_schema(conn)
        finally:
            conn.close()

    def _execute_write(self, fn, *, attempts: int = 5):
        """Run ``fn(conn)`` in a transaction, retrying transient locks."""
        last_exc = None
        for i in range(attempts):
            conn = self._conn()
            try:
                result = fn(conn)
                conn.commit()
                return result
            except sqlite3.OperationalError as exc:
                conn.rollback()
                if any(s in str(exc).lower() for s in _RETRYABLE) and i < attempts - 1:
                    last_exc = exc
                    time.sleep(0.1 * (2 ** i))
                    continue
                raise
            finally:
                conn.close()
        if last_exc:
            raise last_exc

    # ---------------- record read ----------------

    def get_record(self, cve_id: str) -> Optional[CVERecord]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT data FROM cve_records WHERE cve_id=?", (cve_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            return None
        return CVERecord.from_dict(json.loads(row["data"]))

    def get_records(self, cve_ids: List[str]) -> Dict[str, CVERecord]:
        if not cve_ids:
            return {}
        conn = self._conn()
        out: Dict[str, CVERecord] = {}
        try:
            # chunk to keep the IN clause bounded
            for i in range(0, len(cve_ids), 400):
                chunk = cve_ids[i:i + 400]
                q = "SELECT data FROM cve_records WHERE cve_id IN (%s)" % (
                    ",".join("?" * len(chunk)))
                for row in conn.execute(q, chunk).fetchall():
                    rec = CVERecord.from_dict(json.loads(row["data"]))
                    out[rec.cve_id] = rec
        finally:
            conn.close()
        return out

    def exists(self, cve_id: str) -> bool:
        conn = self._conn()
        try:
            return conn.execute(
                "SELECT 1 FROM cve_records WHERE cve_id=?", (cve_id,)).fetchone() is not None
        finally:
            conn.close()

    def content_hash_of(self, cve_id: str) -> Optional[str]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT content_hash FROM cve_records WHERE cve_id=?", (cve_id,)).fetchone()
        finally:
            conn.close()
        return row["content_hash"] if row else None

    # ---------------- record write ----------------

    def save_record(self, rec: CVERecord) -> Tuple[bool, bool]:
        """Insert or update ``rec`` plus its child index rows in one
        transaction. Returns (is_new, content_changed)."""
        chash = _content_hash(rec)
        blob = json.dumps(rec.to_dict(), ensure_ascii=False)
        now = now_epoch()

        def _txn(conn: sqlite3.Connection):
            prev = conn.execute(
                "SELECT content_hash FROM cve_records WHERE cve_id=?",
                (rec.cve_id,)).fetchone()
            is_new = prev is None
            changed = is_new or (prev["content_hash"] != chash)

            conn.execute(
                """INSERT INTO cve_records
                   (cve_id,title,description,published_at,last_modified_at,severity,
                    cvss_score,cvss_version,kev,exploit_maturity,priority,priority_score,
                    ai_state,source_count,content_hash,first_seen_at,enriched_at,updated_at,data)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET
                    title=excluded.title, description=excluded.description,
                    published_at=excluded.published_at,
                    last_modified_at=excluded.last_modified_at,
                    severity=excluded.severity, cvss_score=excluded.cvss_score,
                    cvss_version=excluded.cvss_version, kev=excluded.kev,
                    exploit_maturity=excluded.exploit_maturity,
                    priority=excluded.priority, priority_score=excluded.priority_score,
                    ai_state=excluded.ai_state, source_count=excluded.source_count,
                    content_hash=excluded.content_hash,
                    enriched_at=excluded.enriched_at, updated_at=excluded.updated_at,
                    data=excluded.data""",
                (rec.cve_id, rec.title, rec.description, rec.published_at,
                 rec.last_modified_at, rec.severity, rec.cvss_score, rec.cvss_version,
                 1 if rec.in_kev else 0, rec.exploit_maturity, rec.priority,
                 rec.priority_score, rec.ai_state, len(rec.sources), chash,
                 rec.first_seen_at, rec.enriched_at, now, blob),
            )
            self._sync_children(conn, rec)
            return is_new, changed

        return self._execute_write(_txn)

    def save_records(self, records: List[CVERecord]) -> Dict[str, Tuple[bool, bool]]:
        """Bulk save in one transaction. Returns {cve_id: (is_new, changed)}."""
        if not records:
            return {}
        results: Dict[str, Tuple[bool, bool]] = {}
        now = now_epoch()

        def _txn(conn: sqlite3.Connection):
            for rec in records:
                chash = _content_hash(rec)
                blob = json.dumps(rec.to_dict(), ensure_ascii=False)
                prev = conn.execute(
                    "SELECT content_hash FROM cve_records WHERE cve_id=?",
                    (rec.cve_id,)).fetchone()
                is_new = prev is None
                changed = is_new or (prev["content_hash"] != chash)
                conn.execute(
                    """INSERT INTO cve_records
                       (cve_id,title,description,published_at,last_modified_at,severity,
                        cvss_score,cvss_version,kev,exploit_maturity,priority,priority_score,
                        ai_state,source_count,content_hash,first_seen_at,enriched_at,updated_at,data)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(cve_id) DO UPDATE SET
                        title=excluded.title, description=excluded.description,
                        published_at=excluded.published_at,
                        last_modified_at=excluded.last_modified_at,
                        severity=excluded.severity, cvss_score=excluded.cvss_score,
                        cvss_version=excluded.cvss_version, kev=excluded.kev,
                        exploit_maturity=excluded.exploit_maturity,
                        priority=excluded.priority, priority_score=excluded.priority_score,
                        ai_state=excluded.ai_state, source_count=excluded.source_count,
                        content_hash=excluded.content_hash,
                        enriched_at=excluded.enriched_at, updated_at=excluded.updated_at,
                        data=excluded.data""",
                    (rec.cve_id, rec.title, rec.description, rec.published_at,
                     rec.last_modified_at, rec.severity, rec.cvss_score, rec.cvss_version,
                     1 if rec.in_kev else 0, rec.exploit_maturity, rec.priority,
                     rec.priority_score, rec.ai_state, len(rec.sources), chash,
                     rec.first_seen_at, rec.enriched_at, now, blob),
                )
                self._sync_children(conn, rec)
                results[rec.cve_id] = (is_new, changed)
            return results

        return self._execute_write(_txn)

    def _sync_children(self, conn: sqlite3.Connection, rec: CVERecord) -> None:
        cid = rec.cve_id
        conn.execute("DELETE FROM cve_references WHERE cve_id=?", (cid,))
        conn.execute("DELETE FROM cve_products WHERE cve_id=?", (cid,))
        conn.execute("DELETE FROM cve_cwes WHERE cve_id=?", (cid,))
        conn.execute("DELETE FROM cve_source_records WHERE cve_id=?", (cid,))

        seen_refs = set()
        for r in rec.references:
            if not r.url or r.url in seen_refs:
                continue
            seen_refs.add(r.url)
            conn.execute(
                "INSERT OR IGNORE INTO cve_references(cve_id,url,ref_type,source) VALUES (?,?,?,?)",
                (cid, r.url, r.ref_type, r.source))
        seen_prod = set()
        for p in rec.products:
            vk = slugify(p.vendor)
            pk = slugify(p.product)
            key = (vk, pk)
            if key in seen_prod:
                continue
            seen_prod.add(key)
            conn.execute(
                "INSERT OR IGNORE INTO cve_products(cve_id,vendor,product,vendor_key,product_key) VALUES (?,?,?,?,?)",
                (cid, p.vendor, p.product, vk, pk))
        for w in rec.weaknesses:
            if w.cwe_id:
                conn.execute(
                    "INSERT OR IGNORE INTO cve_cwes(cve_id,cwe_id) VALUES (?,?)",
                    (cid, w.cwe_id))
        for s in rec.sources:
            conn.execute(
                "INSERT OR REPLACE INTO cve_source_records(cve_id,source,source_id,source_url,fetched_at,raw) VALUES (?,?,?,?,?,?)",
                (cid, s.source, s.source_id, s.source_url, s.fetched_at,
                 json.dumps(s.raw, ensure_ascii=False)))

    def update_ai_state(self, cve_id: str, state: str) -> None:
        self._execute_write(lambda c: c.execute(
            "UPDATE cve_records SET ai_state=?, updated_at=? WHERE cve_id=?",
            (state, now_epoch(), cve_id)))

    def update_priority(self, cve_id: str, priority: str, score: int) -> None:
        self._execute_write(lambda c: c.execute(
            "UPDATE cve_records SET priority=?, priority_score=?, updated_at=? WHERE cve_id=?",
            (priority, score, now_epoch(), cve_id)))

    # ---------------- queries ----------------

    def _rows_to_records(self, rows) -> List[CVERecord]:
        return [CVERecord.from_dict(json.loads(r["data"])) for r in rows]

    def recent(self, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT data FROM cve_records
                   ORDER BY COALESCE(published_at, first_seen_at) DESC
                   LIMIT ? OFFSET ?""", (limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def by_severity(self, severity: str, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT data FROM cve_records WHERE severity=?
                   ORDER BY COALESCE(published_at, first_seen_at) DESC
                   LIMIT ? OFFSET ?""",
                (severity.upper(), limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def by_min_cvss(self, min_cvss: float, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT data FROM cve_records WHERE cvss_score >= ?
                   ORDER BY cvss_score DESC, COALESCE(published_at,first_seen_at) DESC
                   LIMIT ? OFFSET ?""", (min_cvss, limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def kev_records(self, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT data FROM cve_records WHERE kev=1
                   ORDER BY COALESCE(published_at, first_seen_at) DESC
                   LIMIT ? OFFSET ?""", (limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def by_vendor(self, vendor: str, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        vk = slugify(vendor)
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT r.data FROM cve_records r
                   JOIN cve_products p ON p.cve_id = r.cve_id
                   WHERE p.vendor_key LIKE ?
                   GROUP BY r.cve_id
                   ORDER BY COALESCE(r.published_at, r.first_seen_at) DESC
                   LIMIT ? OFFSET ?""", (f"%{vk}%", limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def by_product(self, product: str, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        pk = slugify(product)
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT r.data FROM cve_records r
                   JOIN cve_products p ON p.cve_id = r.cve_id
                   WHERE p.product_key LIKE ?
                   GROUP BY r.cve_id
                   ORDER BY COALESCE(r.published_at, r.first_seen_at) DESC
                   LIMIT ? OFFSET ?""", (f"%{pk}%", limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def by_cwe(self, cwe_id: str, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        from ..utils import normalize_cwe_id
        norm = normalize_cwe_id(cwe_id) or cwe_id
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT r.data FROM cve_records r
                   JOIN cve_cwes c ON c.cve_id = r.cve_id
                   WHERE c.cwe_id = ?
                   ORDER BY COALESCE(r.published_at, r.first_seen_at) DESC
                   LIMIT ? OFFSET ?""", (norm, limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def text_search(self, query: str, limit: int = 10, offset: int = 0) -> List[CVERecord]:
        like = f"%{query.strip()}%"
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT data FROM cve_records
                   WHERE cve_id LIKE ? OR title LIKE ? OR description LIKE ?
                   ORDER BY COALESCE(published_at, first_seen_at) DESC
                   LIMIT ? OFFSET ?""",
                (like, like, like, limit, offset)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def published_since(self, since_epoch: int, limit: int = 500) -> List[CVERecord]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT data FROM cve_records
                   WHERE COALESCE(published_at, first_seen_at) >= ?
                   ORDER BY COALESCE(published_at, first_seen_at) DESC LIMIT ?""",
                (since_epoch, limit)).fetchall()
            return self._rows_to_records(rows)
        finally:
            conn.close()

    def count(self) -> int:
        conn = self._conn()
        try:
            return conn.execute("SELECT COUNT(*) AS n FROM cve_records").fetchone()["n"]
        finally:
            conn.close()

    # ---------------- statistics (index-friendly aggregates) ----------------

    def stats(self, *, since_epoch: Optional[int] = None) -> Dict[str, Any]:
        conn = self._conn()
        try:
            out: Dict[str, Any] = {}
            out["total"] = conn.execute(
                "SELECT COUNT(*) n FROM cve_records").fetchone()["n"]
            out["kev"] = conn.execute(
                "SELECT COUNT(*) n FROM cve_records WHERE kev=1").fetchone()["n"]
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) n FROM cve_records GROUP BY severity").fetchall()
            out["by_severity"] = {r["severity"] or "UNKNOWN": r["n"] for r in sev_rows}
            if since_epoch is not None:
                out["since"] = conn.execute(
                    "SELECT COUNT(*) n FROM cve_records WHERE COALESCE(published_at,first_seen_at) >= ?",
                    (since_epoch,)).fetchone()["n"]
                out["critical_since"] = conn.execute(
                    "SELECT COUNT(*) n FROM cve_records WHERE severity='CRITICAL' AND COALESCE(published_at,first_seen_at) >= ?",
                    (since_epoch,)).fetchone()["n"]
            out["top_vendors"] = [
                {"vendor": r["vendor"], "count": r["n"]}
                for r in conn.execute(
                    """SELECT vendor, COUNT(DISTINCT cve_id) n FROM cve_products
                       WHERE vendor != '' GROUP BY vendor_key ORDER BY n DESC LIMIT 8""").fetchall()]
            out["top_cwes"] = [
                {"cwe": r["cwe_id"], "count": r["n"]}
                for r in conn.execute(
                    """SELECT cwe_id, COUNT(DISTINCT cve_id) n FROM cve_cwes
                       GROUP BY cwe_id ORDER BY n DESC LIMIT 8""").fetchall()]
            return out
        finally:
            conn.close()

    # ---------------- source state ----------------

    def get_source_state(self, source: str) -> SourceState:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM cve_source_state WHERE source=?", (source,)).fetchone()
        finally:
            conn.close()
        if not row:
            return SourceState(source=source)
        return SourceState.from_dict({k: row[k] for k in row.keys()})

    def save_source_state(self, state: SourceState) -> None:
        d = state.to_dict()
        self._execute_write(lambda c: c.execute(
            """INSERT INTO cve_source_state
               (source,enabled,last_success_at,last_failure_at,last_cursor,
                last_modified_seen,etag,http_last_modified,consecutive_failures,
                total_runs,records_seen,records_new,records_updated,records_duplicate,
                last_latency_ms,health,last_error)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(source) DO UPDATE SET
                enabled=excluded.enabled, last_success_at=excluded.last_success_at,
                last_failure_at=excluded.last_failure_at, last_cursor=excluded.last_cursor,
                last_modified_seen=excluded.last_modified_seen, etag=excluded.etag,
                http_last_modified=excluded.http_last_modified,
                consecutive_failures=excluded.consecutive_failures,
                total_runs=excluded.total_runs, records_seen=excluded.records_seen,
                records_new=excluded.records_new, records_updated=excluded.records_updated,
                records_duplicate=excluded.records_duplicate,
                last_latency_ms=excluded.last_latency_ms, health=excluded.health,
                last_error=excluded.last_error""",
            (d["source"], 1 if d["enabled"] else 0, d["last_success_at"],
             d["last_failure_at"], d["last_cursor"], d["last_modified_seen"],
             d["etag"], d["http_last_modified"], d["consecutive_failures"],
             d["total_runs"], d["records_seen"], d["records_new"], d["records_updated"],
             d["records_duplicate"], d["last_latency_ms"], d["health"], d["last_error"])))

    def all_source_states(self) -> List[SourceState]:
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM cve_source_state").fetchall()
            return [SourceState.from_dict({k: r[k] for k in r.keys()}) for r in rows]
        finally:
            conn.close()

    # ---------------- notifications ----------------

    def notification_exists(self, dedupe_key: str) -> bool:
        conn = self._conn()
        try:
            return conn.execute(
                "SELECT 1 FROM cve_notifications WHERE dedupe_key=?",
                (dedupe_key,)).fetchone() is not None
        finally:
            conn.close()

    def record_notification(self, n: Notification) -> Optional[int]:
        """Insert a notification if its dedupe_key is new. Returns the row id,
        or None if it already existed (idempotency)."""
        def _txn(conn):
            try:
                cur = conn.execute(
                    """INSERT INTO cve_notifications
                       (dedupe_key,cve_id,chat_id,topic_id,reason,state,priority,
                        is_update,attempts,created_at,sent_at,error)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (n.dedupe_key, n.cve_id, n.chat_id, n.topic_id, n.reason, n.state,
                     n.priority, 1 if n.is_update else 0, n.attempts, n.created_at,
                     n.sent_at, n.error))
                return cur.lastrowid
            except sqlite3.IntegrityError:
                return None
        return self._execute_write(_txn)

    def mark_notification(self, dedupe_key: str, state: str, *, error: str = "") -> None:
        self._execute_write(lambda c: c.execute(
            """UPDATE cve_notifications
               SET state=?, sent_at=?, attempts=attempts+1, error=?
               WHERE dedupe_key=?""",
            (state, now_epoch() if state == "sent" else None, error, dedupe_key)))

    def pending_notifications(self, limit: int = 100) -> List[Notification]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT * FROM cve_notifications
                   WHERE state IN ('pending','retry','queued')
                   ORDER BY created_at ASC LIMIT ?""", (limit,)).fetchall()
            return [Notification.from_dict({
                "cve_id": r["cve_id"], "chat_id": r["chat_id"], "topic_id": r["topic_id"],
                "reason": r["reason"], "state": r["state"], "priority": r["priority"],
                "is_update": bool(r["is_update"]), "attempts": r["attempts"],
                "created_at": r["created_at"], "sent_at": r["sent_at"], "error": r["error"],
            }) for r in rows]
        finally:
            conn.close()

    def notification_stats(self, *, since_epoch: Optional[int] = None) -> Dict[str, int]:
        conn = self._conn()
        try:
            where = "WHERE created_at >= ?" if since_epoch is not None else ""
            args = (since_epoch,) if since_epoch is not None else ()
            rows = conn.execute(
                f"SELECT state, COUNT(*) n FROM cve_notifications {where} GROUP BY state",
                args).fetchall()
            return {r["state"]: r["n"] for r in rows}
        finally:
            conn.close()

    # ---------------- subscriptions ----------------

    def upsert_subscription(self, sub: Subscription) -> None:
        data = json.dumps(sub.to_dict(), ensure_ascii=False)
        topic = sub.topic_id or 0
        self._execute_write(lambda c: c.execute(
            """INSERT INTO cve_subscriptions(chat_id,topic_id,enabled,data,created_at,updated_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(chat_id,topic_id) DO UPDATE SET
                enabled=excluded.enabled, data=excluded.data, updated_at=excluded.updated_at""",
            (sub.chat_id, topic, 1 if sub.enabled else 0, data,
             sub.created_at, now_epoch())))

    def get_subscription(self, chat_id: int, topic_id: int = 0) -> Optional[Subscription]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT data FROM cve_subscriptions WHERE chat_id=? AND topic_id=?",
                (chat_id, topic_id or 0)).fetchone()
        finally:
            conn.close()
        return Subscription.from_dict(json.loads(row["data"])) if row else None

    def list_subscriptions(self, *, enabled_only: bool = True) -> List[Subscription]:
        conn = self._conn()
        try:
            q = "SELECT data FROM cve_subscriptions"
            if enabled_only:
                q += " WHERE enabled=1"
            rows = conn.execute(q).fetchall()
            return [Subscription.from_dict(json.loads(r["data"])) for r in rows]
        finally:
            conn.close()

    def delete_subscription(self, chat_id: int, topic_id: int = 0) -> None:
        self._execute_write(lambda c: c.execute(
            "DELETE FROM cve_subscriptions WHERE chat_id=? AND topic_id=?",
            (chat_id, topic_id or 0)))

    # ---------------- AI summaries ----------------

    def save_ai_summary(self, summary: AISummary) -> None:
        data = json.dumps(summary.to_dict(), ensure_ascii=False)
        self._execute_write(lambda c: c.execute(
            """INSERT INTO cve_ai_summaries(cve_id,input_hash,language,data,provider,model,fallback,created_at)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(cve_id,input_hash) DO UPDATE SET
                data=excluded.data, provider=excluded.provider, model=excluded.model,
                fallback=excluded.fallback, created_at=excluded.created_at""",
            (summary.cve_id, summary.input_hash, summary.language, data,
             summary.provider, summary.model, 1 if summary.fallback_used else 0,
             summary.created_at)))

    def get_ai_summary(self, cve_id: str, input_hash: str) -> Optional[AISummary]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT data FROM cve_ai_summaries WHERE cve_id=? AND input_hash=?",
                (cve_id, input_hash)).fetchone()
        finally:
            conn.close()
        return AISummary.from_dict(json.loads(row["data"])) if row else None

    def get_latest_ai_summary(self, cve_id: str) -> Optional[AISummary]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT data FROM cve_ai_summaries WHERE cve_id=? ORDER BY created_at DESC LIMIT 1",
                (cve_id,)).fetchone()
        finally:
            conn.close()
        return AISummary.from_dict(json.loads(row["data"])) if row else None

    # ---------------- events / failures / audit / runs ----------------

    def log_event(self, event_type: str, cve_id: str = "", payload: Optional[dict] = None) -> None:
        self._execute_write(lambda c: c.execute(
            "INSERT INTO cve_events(cve_id,event_type,payload,created_at) VALUES (?,?,?,?)",
            (cve_id or None, event_type,
             json.dumps(payload or {}, ensure_ascii=False), now_epoch())))

    def recent_events(self, limit: int = 20, event_type: str = "") -> List[dict]:
        conn = self._conn()
        try:
            if event_type:
                rows = conn.execute(
                    "SELECT * FROM cve_events WHERE event_type=? ORDER BY created_at DESC LIMIT ?",
                    (event_type, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM cve_events ORDER BY created_at DESC LIMIT ?",
                    (limit,)).fetchall()
            return [{"id": r["id"], "cve_id": r["cve_id"], "event_type": r["event_type"],
                     "payload": json.loads(r["payload"] or "{}"),
                     "created_at": r["created_at"]} for r in rows]
        finally:
            conn.close()

    def record_failure(self, source: str, cve_id: str, reason: str) -> None:
        self._execute_write(lambda c: c.execute(
            "INSERT INTO cve_failures(source,cve_id,reason,created_at) VALUES (?,?,?,?)",
            (source, cve_id, reason[:500], now_epoch())))

    def audit(self, event: str, *, actor: str = "system", cve_id: str = "",
              result: str = "ok", metadata: Optional[dict] = None) -> None:
        self._execute_write(lambda c: c.execute(
            "INSERT INTO cve_audit_log(at,actor,event,cve_id,result,metadata) VALUES (?,?,?,?,?,?)",
            (now_epoch(), actor, event, cve_id or None, result,
             json.dumps(metadata or {}, ensure_ascii=False))))

    def start_run(self, sources: List[str]) -> int:
        def _txn(conn):
            cur = conn.execute(
                "INSERT INTO cve_ingestion_runs(started_at,sources) VALUES (?,?)",
                (now_epoch(), ",".join(sources)))
            return cur.lastrowid
        return self._execute_write(_txn)

    def finish_run(self, run_id: int, *, seen: int, new: int, updated: int,
                   failed: int, ok: bool, note: str = "") -> None:
        self._execute_write(lambda c: c.execute(
            """UPDATE cve_ingestion_runs
               SET finished_at=?, records_seen=?, records_new=?, records_updated=?,
                   records_failed=?, ok=?, note=? WHERE id=?""",
            (now_epoch(), seen, new, updated, failed, 1 if ok else 0, note, run_id)))

    # ---------------- meta ----------------

    def get_meta(self, key: str, default: str = "") -> str:
        conn = self._conn()
        try:
            row = conn.execute("SELECT value FROM cve_meta WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default
        finally:
            conn.close()

    def set_meta(self, key: str, value: str) -> None:
        self._execute_write(lambda c: c.execute(
            "INSERT INTO cve_meta(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value))))
