"""
cybersecurity_intelligence.storage.store — the CTI analysis SQLite store.

Holds the analytic-layer records: graded sources, consolidated claims,
contradictions and finished assessments. It intentionally does **not** duplicate
the actor/campaign/malware/IOC tables owned by
``threat_actor_intelligence.storage.sqlite_store`` — this layer references those by
canonical id/value through the claim ``subject`` and reads the same evidence. Its
own tables are ``cti_``-prefixed.

Search uses SQLite FTS5 when available (probed once at init); otherwise it falls
back to a ``LIKE`` scan so behaviour is identical minus ranking.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from ..exceptions import CTIStorageError
from ..models.assessment import Assessment
from ..models.claim import Claim
from ..models.contradiction import Contradiction
from ..models.source import SourceRecord

DEFAULT_DB_PATH = "cybersecurity_intelligence.db"
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cti_schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS cti_sources (
    source_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    source_class TEXT NOT NULL DEFAULT 'unknown',
    grade        TEXT NOT NULL DEFAULT 'unknown',
    score        REAL NOT NULL DEFAULT 0,
    first_seen   REAL NOT NULL DEFAULT 0,
    last_seen    REAL NOT NULL DEFAULT 0,
    data         TEXT NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cti_sources_name ON cti_sources(name);
CREATE INDEX IF NOT EXISTS ix_cti_sources_grade ON cti_sources(grade);

CREATE TABLE IF NOT EXISTS cti_claims (
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
);
CREATE INDEX IF NOT EXISTS ix_cti_claims_subject ON cti_claims(subject_key);
CREATE INDEX IF NOT EXISTS ix_cti_claims_type ON cti_claims(claim_type);
CREATE INDEX IF NOT EXISTS ix_cti_claims_subjtype ON cti_claims(subject_type);

CREATE TABLE IF NOT EXISTS cti_contradictions (
    contradiction_id   TEXT PRIMARY KEY,
    contradiction_type TEXT NOT NULL,
    subject_key        TEXT NOT NULL,
    data               TEXT NOT NULL,
    detected_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cti_contra_subject ON cti_contradictions(subject_key);
CREATE INDEX IF NOT EXISTS ix_cti_contra_type ON cti_contradictions(contradiction_type);

CREATE TABLE IF NOT EXISTS cti_assessments (
    assessment_id TEXT PRIMARY KEY,
    subject_key   TEXT NOT NULL,
    title         TEXT NOT NULL,
    priority      TEXT NOT NULL DEFAULT 'informational',
    score         REAL NOT NULL DEFAULT 0,
    band          TEXT DEFAULT 'very low',
    data          TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cti_assess_subject ON cti_assessments(subject_key);
CREATE INDEX IF NOT EXISTS ix_cti_assess_priority ON cti_assessments(priority);
"""


class CTIStore:
    """SQLite persistence for the CTI analysis layer."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._fts = False
        self.init_db()

    # -- connection -------------------------------------------------------- #

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn()
        try:
            yield conn
            conn.commit()
        except sqlite3.Error as exc:  # pragma: no cover - surfaced as CTIStorageError
            conn.rollback()
            raise CTIStorageError(str(exc)) from exc
        finally:
            conn.close()

    def init_db(self) -> None:
        with self._tx() as conn:
            conn.executescript(_SCHEMA)
            self._fts = self._probe_fts(conn)
            if self._fts:
                conn.executescript(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS cti_claims_fts USING fts5("
                    "claim_id UNINDEXED, subject_value, statement, tags);")
            row = conn.execute(
                "SELECT MAX(version) v FROM cti_schema_migrations").fetchone()
            if not row or row["v"] is None:
                conn.execute(
                    "INSERT OR IGNORE INTO cti_schema_migrations (version, applied_at) "
                    "VALUES (?,?)", (SCHEMA_VERSION, time.time()))

    @staticmethod
    def _probe_fts(conn: sqlite3.Connection) -> bool:
        try:
            conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _cti_fts_probe "
                         "USING fts5(x);")
            conn.execute("DROP TABLE IF EXISTS _cti_fts_probe;")
            return True
        except sqlite3.Error:
            return False

    @property
    def fts_enabled(self) -> bool:
        return self._fts

    # -- sources ----------------------------------------------------------- #

    def save_source(self, source: SourceRecord) -> None:
        d = source.to_dict()
        rel = d.get("reliability") or {}
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO cti_sources
                   (source_id,name,source_class,grade,score,first_seen,last_seen,
                    data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(source_id) DO UPDATE SET
                     name=excluded.name, source_class=excluded.source_class,
                     grade=excluded.grade, score=excluded.score,
                     last_seen=MAX(cti_sources.last_seen, excluded.last_seen),
                     data=excluded.data, updated_at=excluded.updated_at""",
                (source.source_id, source.name, source.source_class.value,
                 rel.get("grade", "unknown"), float(rel.get("score", 0.0) or 0.0),
                 source.first_seen, source.last_seen,
                 json.dumps(d, ensure_ascii=False), time.time()))

    def get_source(self, source_id: str) -> Optional[SourceRecord]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM cti_sources WHERE source_id=?",
                               (source_id,)).fetchone()
        return SourceRecord.from_dict(json.loads(row["data"])) if row else None

    def iter_sources(self, *, limit: int = 0) -> Iterator[SourceRecord]:
        q = "SELECT data FROM cti_sources ORDER BY last_seen DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q):
                yield SourceRecord.from_dict(json.loads(row["data"]))

    # -- claims ------------------------------------------------------------ #

    def save_claim(self, claim: Claim) -> None:
        self.save_claims([claim])

    def save_claims(self, claims: List[Claim]) -> int:
        now = time.time()
        n = 0
        with self._tx() as conn:
            for claim in claims:
                d = claim.to_dict()
                conn.execute(
                    """INSERT INTO cti_claims
                       (claim_id,subject_type,subject_value,subject_key,claim_type,
                        predicate,score,band,independent_sources,observed_at,
                        first_seen,last_seen,data,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(claim_id) DO UPDATE SET
                         claim_type=excluded.claim_type, score=excluded.score,
                         band=excluded.band,
                         independent_sources=excluded.independent_sources,
                         last_seen=MAX(cti_claims.last_seen, excluded.last_seen),
                         data=excluded.data, updated_at=excluded.updated_at""",
                    (claim.claim_id, claim.subject.ref_type, claim.subject.ref_value,
                     claim.subject.key(), claim.claim_type.value, claim.predicate,
                     round(claim.score, 4), claim.band,
                     claim.independent_source_count(), claim.observed_at,
                     claim.first_seen, claim.last_seen,
                     json.dumps(d, ensure_ascii=False), now))
                if self._fts:
                    conn.execute("DELETE FROM cti_claims_fts WHERE claim_id=?",
                                 (claim.claim_id,))
                    conn.execute(
                        "INSERT INTO cti_claims_fts (claim_id,subject_value,statement,tags) "
                        "VALUES (?,?,?,?)",
                        (claim.claim_id, claim.subject.ref_value, claim.statement,
                         " ".join(claim.tags)))
                n += 1
        return n

    def get_claim(self, claim_id: str) -> Optional[Claim]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM cti_claims WHERE claim_id=?",
                               (claim_id,)).fetchone()
        return Claim.from_dict(json.loads(row["data"])) if row else None

    def claims_for_subject(self, subject_key: str, *, limit: int = 0) -> List[Claim]:
        q = "SELECT data FROM cti_claims WHERE subject_key=? ORDER BY score DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            rows = conn.execute(q, (subject_key.lower(),)).fetchall()
        return [Claim.from_dict(json.loads(r["data"])) for r in rows]

    def iter_claims(self, *, claim_type: str = "", subject_type: str = "",
                    limit: int = 0) -> Iterator[Claim]:
        q = "SELECT data FROM cti_claims"
        clauses: List[str] = []
        params: List[Any] = []
        if claim_type:
            clauses.append("claim_type=?")
            params.append(claim_type)
        if subject_type:
            clauses.append("subject_type=?")
            params.append(subject_type)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY last_seen DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q, params):
                yield Claim.from_dict(json.loads(row["data"]))

    def search_claims(self, query: str, *, limit: int = 50) -> List[Claim]:
        query = (query or "").strip()
        if not query:
            return []
        with self._tx() as conn:
            if self._fts:
                try:
                    rows = conn.execute(
                        "SELECT c.data FROM cti_claims_fts f "
                        "JOIN cti_claims c ON c.claim_id=f.claim_id "
                        "WHERE cti_claims_fts MATCH ? "
                        "ORDER BY rank LIMIT ?", (query, int(limit))).fetchall()
                    return [Claim.from_dict(json.loads(r["data"])) for r in rows]
                except sqlite3.Error:
                    pass  # fall through to LIKE
            like = f"%{query}%"
            rows = conn.execute(
                "SELECT data FROM cti_claims WHERE subject_value LIKE ? "
                "OR data LIKE ? ORDER BY score DESC LIMIT ?",
                (like, like, int(limit))).fetchall()
        return [Claim.from_dict(json.loads(r["data"])) for r in rows]

    # -- contradictions ---------------------------------------------------- #

    def save_contradiction(self, c: Contradiction) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO cti_contradictions
                   (contradiction_id,contradiction_type,subject_key,data,detected_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(contradiction_id) DO UPDATE SET
                     data=excluded.data, detected_at=excluded.detected_at""",
                (c.contradiction_id, c.contradiction_type.value, c.subject_key,
                 json.dumps(c.to_dict(), ensure_ascii=False), c.detected_at))

    def save_contradictions(self, items: List[Contradiction]) -> int:
        for c in items:
            self.save_contradiction(c)
        return len(items)

    def contradictions_for_subject(self, subject_key: str) -> List[Contradiction]:
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT data FROM cti_contradictions WHERE subject_key=? "
                "ORDER BY detected_at DESC", (subject_key,)).fetchall()
        return [Contradiction.from_dict(json.loads(r["data"])) for r in rows]

    def iter_contradictions(self, *, limit: int = 0) -> Iterator[Contradiction]:
        q = "SELECT data FROM cti_contradictions ORDER BY detected_at DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q):
                yield Contradiction.from_dict(json.loads(row["data"]))

    # -- assessments ------------------------------------------------------- #

    def save_assessment(self, a: Assessment) -> None:
        score = a.overall_confidence.score if a.overall_confidence else 0.0
        band = a.overall_confidence.band if a.overall_confidence else "very low"
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO cti_assessments
                   (assessment_id,subject_key,title,priority,score,band,data,created_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(assessment_id) DO UPDATE SET
                     title=excluded.title, priority=excluded.priority,
                     score=excluded.score, band=excluded.band, data=excluded.data""",
                (a.assessment_id, a.subject_key, a.title, a.priority.value,
                 round(score, 4), band, json.dumps(a.to_dict(), ensure_ascii=False),
                 a.created_at))

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM cti_assessments WHERE assessment_id=?",
                               (assessment_id,)).fetchone()
        return Assessment.from_dict(json.loads(row["data"])) if row else None

    def latest_assessment_for(self, subject_key: str) -> Optional[Assessment]:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT data FROM cti_assessments WHERE subject_key=? "
                "ORDER BY created_at DESC LIMIT 1", (subject_key,)).fetchone()
        return Assessment.from_dict(json.loads(row["data"])) if row else None

    def iter_assessments(self, *, priority: str = "", limit: int = 0
                         ) -> Iterator[Assessment]:
        q = "SELECT data FROM cti_assessments"
        params: List[Any] = []
        if priority:
            q += " WHERE priority=?"
            params.append(priority)
        q += " ORDER BY created_at DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q, params):
                yield Assessment.from_dict(json.loads(row["data"]))

    # -- stats ------------------------------------------------------------- #

    def stats(self) -> Dict[str, Any]:
        with self._tx() as conn:
            def count(t: str) -> int:
                return conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]
            return {
                "db_path": self.db_path,
                "fts_enabled": self._fts,
                "sources": count("cti_sources"),
                "claims": count("cti_claims"),
                "contradictions": count("cti_contradictions"),
                "assessments": count("cti_assessments"),
            }


__all__ = ["CTIStore", "DEFAULT_DB_PATH", "SCHEMA_VERSION"]
