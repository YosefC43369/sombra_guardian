"""
behavioral_intelligence.storage.sqlite_store — durable persistence for
observations and analytical results (spec §35).

Standard-library ``sqlite3`` only, matching ``entity_fusion.storage.sqlite_store``
and the repo's other data modules (CREATE TABLE IF NOT EXISTS, explicit indexes,
WAL, short-lived per-operation connections so it is safe alongside async code).

Schema (all prefixed ``behavior_``):
  behavior_observations   one row per observation (indexed by entity/platform/ts)
  behavior_activity       stored activity aggregates per entity/window
  behavior_languages      language distribution rows
  behavior_topics         topic/keyword rows
  behavior_hashtags       hashtag rows
  behavior_domains        domain rows
  behavior_interactions   directed interaction edges
  behavior_anomalies      detected anomalies
  behavior_baselines      stored baselines (JSON blob)
  behavior_change_points  detected change points
  behavior_evidence       evidence references
Indexes are created for every column the engines query on. The design supports
incremental processing: observations upsert by observation_id and expose a
``since``-filtered read so a run only re-aggregates new data.
"""

from __future__ import annotations

import json
import time
import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..models.observation import Observation

DEFAULT_DB_PATH = "behavioral_intelligence.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS behavior_observations (
    observation_id TEXT PRIMARY KEY,
    entity_id      TEXT NOT NULL DEFAULT '',
    platform       TEXT NOT NULL DEFAULT '',
    account_id     TEXT NOT NULL DEFAULT '',
    timestamp      REAL NOT NULL DEFAULT 0,
    content_type   TEXT NOT NULL DEFAULT '',
    language       TEXT NOT NULL DEFAULT '',
    content_hash   TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT '',
    evidence_id    TEXT NOT NULL DEFAULT '',
    dedupe_key     TEXT NOT NULL DEFAULT '',
    collected_at   REAL NOT NULL DEFAULT 0,
    data           TEXT NOT NULL,
    updated_at     REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_obs_entity_ts ON behavior_observations(entity_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_obs_platform ON behavior_observations(platform, account_id);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON behavior_observations(timestamp);
CREATE INDEX IF NOT EXISTS idx_obs_hash ON behavior_observations(content_hash);
CREATE INDEX IF NOT EXISTS idx_obs_dedupe ON behavior_observations(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_obs_collected ON behavior_observations(collected_at);

CREATE TABLE IF NOT EXISTS behavior_activity (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id    TEXT NOT NULL,
    window_days  INTEGER NOT NULL DEFAULT 0,
    generated_at REAL NOT NULL,
    data         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_entity ON behavior_activity(entity_id, generated_at);

CREATE TABLE IF NOT EXISTS behavior_languages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id  TEXT NOT NULL,
    language   TEXT NOT NULL,
    share      REAL NOT NULL DEFAULT 0,
    count      INTEGER NOT NULL DEFAULT 0,
    period_start REAL NOT NULL DEFAULT 0,
    period_end   REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_lang_entity ON behavior_languages(entity_id);

CREATE TABLE IF NOT EXISTS behavior_topics (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id  TEXT NOT NULL,
    term       TEXT NOT NULL,
    tfidf      REAL NOT NULL DEFAULT 0,
    frequency  INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL DEFAULT 0,
    last_seen  REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_topic_entity ON behavior_topics(entity_id, tfidf);

CREATE TABLE IF NOT EXISTS behavior_hashtags (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id  TEXT NOT NULL,
    tag        TEXT NOT NULL,
    frequency  INTEGER NOT NULL DEFAULT 0,
    trend      TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL DEFAULT 0,
    last_seen  REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hashtag_entity ON behavior_hashtags(entity_id, frequency);

CREATE TABLE IF NOT EXISTS behavior_domains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id  TEXT NOT NULL,
    domain     TEXT NOT NULL,
    frequency  INTEGER NOT NULL DEFAULT 0,
    is_shortener INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL DEFAULT 0,
    last_seen  REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_domain_entity ON behavior_domains(entity_id, frequency);

CREATE TABLE IF NOT EXISTS behavior_interactions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id  TEXT NOT NULL,
    source     TEXT NOT NULL,
    target     TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL DEFAULT 0,
    last_seen  REAL NOT NULL DEFAULT 0,
    data       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_interaction_entity ON behavior_interactions(entity_id);
CREATE INDEX IF NOT EXISTS idx_interaction_src ON behavior_interactions(source);
CREATE INDEX IF NOT EXISTS idx_interaction_tgt ON behavior_interactions(target);

CREATE TABLE IF NOT EXISTS behavior_anomalies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id  TEXT NOT NULL,
    at         REAL NOT NULL DEFAULT 0,
    kind       TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT '',
    data       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anomaly_entity ON behavior_anomalies(entity_id, at);

CREATE TABLE IF NOT EXISTS behavior_baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id   TEXT NOT NULL,
    window_days INTEGER NOT NULL DEFAULT 0,
    generated_at REAL NOT NULL,
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_baseline_entity ON behavior_baselines(entity_id, window_days);

CREATE TABLE IF NOT EXISTS behavior_change_points (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id  TEXT NOT NULL,
    at         REAL NOT NULL DEFAULT 0,
    kind       TEXT NOT NULL DEFAULT '',
    method     TEXT NOT NULL DEFAULT '',
    magnitude  REAL NOT NULL DEFAULT 0,
    data       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cp_entity ON behavior_change_points(entity_id, at);

CREATE TABLE IF NOT EXISTS behavior_evidence (
    evidence_id  TEXT PRIMARY KEY,
    observation_id TEXT NOT NULL DEFAULT '',
    provider     TEXT NOT NULL DEFAULT '',
    source_url   TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    timestamp    REAL NOT NULL DEFAULT 0,
    collected_at REAL NOT NULL DEFAULT 0,
    confidence   REAL NOT NULL DEFAULT 1.0,
    data         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_obs ON behavior_evidence(observation_id);

CREATE TABLE IF NOT EXISTS behavior_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id   TEXT NOT NULL,
    created_at  REAL NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshot_entity ON behavior_snapshots(entity_id, created_at);
"""


class SQLiteStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    # -- observations ------------------------------------------------------ #

    def save_observation(self, obs: Observation) -> None:
        self.save_observations([obs])

    def save_observations(self, observations: Sequence[Observation]) -> int:
        now = time.time()
        rows = []
        for o in observations:
            payload = json.dumps(o.to_dict(), ensure_ascii=False, sort_keys=True)
            rows.append((o.observation_id, o.entity_id, o.platform, o.account_id,
                         o.timestamp, o.content_type.value, o.language,
                         o.content_hash, o.source, o.evidence_id, o.dedupe_key(),
                         o.collected_at, payload, now))
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO behavior_observations
                   (observation_id,entity_id,platform,account_id,timestamp,
                    content_type,language,content_hash,source,evidence_id,
                    dedupe_key,collected_at,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(observation_id) DO UPDATE SET
                     entity_id=excluded.entity_id, platform=excluded.platform,
                     account_id=excluded.account_id, timestamp=excluded.timestamp,
                     content_type=excluded.content_type, language=excluded.language,
                     content_hash=excluded.content_hash, source=excluded.source,
                     evidence_id=excluded.evidence_id, dedupe_key=excluded.dedupe_key,
                     data=excluded.data, updated_at=excluded.updated_at""",
                rows)
        return len(rows)

    def load_observations(self, *, entity_id: Optional[str] = None,
                          platform: Optional[str] = None,
                          since: Optional[float] = None,
                          until: Optional[float] = None,
                          limit: int = 1_000_000) -> List[Observation]:
        clauses: List[str] = []
        params: List[Any] = []
        if entity_id is not None:
            clauses.append("entity_id=?")
            params.append(entity_id)
        if platform is not None:
            clauses.append("platform=?")
            params.append(platform)
        if since is not None:
            clauses.append("timestamp>=?")
            params.append(since)
        if until is not None:
            clauses.append("timestamp<=?")
            params.append(until)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT data FROM behavior_observations {where} "
                f"ORDER BY timestamp ASC LIMIT ?", (*params, limit)).fetchall()
        return [Observation.from_dict(json.loads(r["data"])) for r in rows]

    def iter_observations(self, *, entity_id: Optional[str] = None,
                          batch_size: int = 5000) -> Iterable[Observation]:
        """Stream observations for an entity without loading all into RAM
        (large-dataset mode, spec §38). Uses keyset pagination on timestamp."""
        last_ts = -1.0
        last_id = ""
        while True:
            clauses = ["(timestamp>? OR (timestamp=? AND observation_id>?))"]
            params: List[Any] = [last_ts, last_ts, last_id]
            if entity_id is not None:
                clauses.append("entity_id=?")
                params.append(entity_id)
            with self._conn() as conn:
                rows = conn.execute(
                    f"SELECT observation_id,timestamp,data FROM behavior_observations "
                    f"WHERE {' AND '.join(clauses)} "
                    f"ORDER BY timestamp ASC, observation_id ASC LIMIT ?",
                    (*params, batch_size)).fetchall()
            if not rows:
                return
            for r in rows:
                yield Observation.from_dict(json.loads(r["data"]))
            last_ts = rows[-1]["timestamp"]
            last_id = rows[-1]["observation_id"]
            if len(rows) < batch_size:
                return

    def delete_observation(self, observation_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM behavior_observations WHERE observation_id=?",
                        (observation_id,))

    def prune_observations(self, older_than: float) -> int:
        """Delete observations with collected_at older than a cutoff (TTL,
        spec §34). Returns the number removed."""
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM behavior_observations WHERE collected_at>0 AND collected_at<?",
                (older_than,))
            return cur.rowcount

    def max_collected_at(self, entity_id: Optional[str] = None) -> float:
        clause = "WHERE entity_id=?" if entity_id is not None else ""
        params = (entity_id,) if entity_id is not None else ()
        with self._conn() as conn:
            row = conn.execute(
                f"SELECT MAX(collected_at) m FROM behavior_observations {clause}",
                params).fetchone()
        return float(row["m"] or 0.0)

    # -- analytical result rows ------------------------------------------- #

    def save_baseline(self, baseline) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO behavior_baselines
                   (entity_id,window_days,generated_at,data) VALUES (?,?,?,?)""",
                (baseline.entity_id, baseline.window_days, time.time(),
                 json.dumps(baseline.to_dict(), ensure_ascii=False)))

    def latest_baseline(self, entity_id: str, window_days: int) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                """SELECT data FROM behavior_baselines
                   WHERE entity_id=? AND window_days=?
                   ORDER BY generated_at DESC LIMIT 1""",
                (entity_id, window_days)).fetchone()
        return json.loads(row["data"]) if row else None

    def save_anomalies(self, anomalies: Sequence) -> int:
        rows = [(a.entity_id, a.at, a.kind, a.severity,
                 json.dumps(a.to_dict(), ensure_ascii=False)) for a in anomalies]
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO behavior_anomalies (entity_id,at,kind,severity,data)
                   VALUES (?,?,?,?,?)""", rows)
        return len(rows)

    def save_change_points(self, entity_id: str, change_points: Sequence) -> int:
        rows = [(entity_id, c.at, c.kind, c.method, c.magnitude,
                 json.dumps(c.to_dict(), ensure_ascii=False)) for c in change_points]
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO behavior_change_points
                   (entity_id,at,kind,method,magnitude,data) VALUES (?,?,?,?,?,?)""",
                rows)
        return len(rows)

    def save_interactions(self, entity_id: str, edges: Sequence) -> int:
        rows = [(entity_id, e.source, e.target, e.count, e.first_seen, e.last_seen,
                 json.dumps(e.to_dict(), ensure_ascii=False)) for e in edges]
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO behavior_interactions
                   (entity_id,source,target,count,first_seen,last_seen,data)
                   VALUES (?,?,?,?,?,?,?)""", rows)
        return len(rows)

    def save_evidence(self, refs: Sequence) -> int:
        rows = [(r.observation_id or r.key(), r.observation_id, r.provider,
                 r.source_url, r.content_hash, r.timestamp, r.collected_at,
                 r.confidence, json.dumps(r.to_dict(), ensure_ascii=False))
                for r in refs]
        with self._conn() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO behavior_evidence
                   (evidence_id,observation_id,provider,source_url,content_hash,
                    timestamp,collected_at,confidence,data)
                   VALUES (?,?,?,?,?,?,?,?,?)""", rows)
        return len(rows)

    def save_snapshot(self, entity_id: str, profile_dict: Dict[str, Any],
                      label: str = "") -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO behavior_snapshots (entity_id,created_at,label,data)
                   VALUES (?,?,?,?)""",
                (entity_id, time.time(), label,
                 json.dumps(profile_dict, ensure_ascii=False)))
            return int(cur.lastrowid or 0)

    def list_snapshots(self, entity_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id,created_at,label FROM behavior_snapshots
                   WHERE entity_id=? ORDER BY created_at""", (entity_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_snapshot(self, snapshot_id: int) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM behavior_snapshots WHERE id=?",
                              (snapshot_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def stats(self) -> Dict[str, Any]:
        with self._conn() as conn:
            def count(table: str) -> int:
                return conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
            return {
                "db_path": self.db_path,
                "observations": count("behavior_observations"),
                "anomalies": count("behavior_anomalies"),
                "baselines": count("behavior_baselines"),
                "change_points": count("behavior_change_points"),
                "interactions": count("behavior_interactions"),
                "evidence": count("behavior_evidence"),
                "snapshots": count("behavior_snapshots"),
            }
