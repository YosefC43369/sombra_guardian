"""
entity_fusion.storage.sqlite_store — durable persistence for entities,
relationships, evidence, history and a generic cache.

Standard-library ``sqlite3`` only, matching the discipline of ``scope_policy`` /
``security`` / ``osint_db`` (CREATE TABLE IF NOT EXISTS, explicit indexes, no
ORM). The store round-trips ``Entity`` objects losslessly via their ``to_dict``
form: scalar columns are duplicated out for indexed querying, while the full
object is kept as a JSON blob so nothing is lost.

Schema
------
  entities              one row per entity (indexed by type + normalized value)
  entity_aliases        (entity_id, alias)         — many per entity
  entity_relationships  (src_id, dst_id, type, weight)
  entity_evidence       (entity_id, kind, value, weight, source_json)
  entity_history        append-only change log (temporal engine feeds this)
  entity_cache          generic (namespace, key) → value blob with TTL

Concurrency: SQLite with WAL and a per-connection pattern. The store opens a
short-lived connection per operation (like the other modules here) so it is safe
to use from async code without sharing a connection across the event loop.
"""

from __future__ import annotations

import json
import time
import sqlite3
from typing import Any, Dict, List, Optional

from ..entity import Entity, EntityType, Relationship, Evidence, SourceRef

DEFAULT_DB_PATH = "entity_fusion.db"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    value        TEXT NOT NULL,
    normalized   TEXT NOT NULL,
    confidence   REAL NOT NULL DEFAULT 0,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    data         TEXT NOT NULL,            -- full Entity.to_dict() as JSON
    updated_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entities_type_norm ON entities(type, normalized);
CREATE INDEX IF NOT EXISTS idx_entities_normalized ON entities(normalized);

CREATE TABLE IF NOT EXISTS entity_aliases (
    entity_id  TEXT NOT NULL,
    alias      TEXT NOT NULL,
    PRIMARY KEY (entity_id, alias)
);
CREATE INDEX IF NOT EXISTS idx_aliases_alias ON entity_aliases(alias);

CREATE TABLE IF NOT EXISTS entity_relationships (
    src_id     TEXT NOT NULL,
    dst_id     TEXT NOT NULL,
    type       TEXT NOT NULL,
    weight     REAL NOT NULL DEFAULT 1.0,
    source     TEXT DEFAULT '',
    PRIMARY KEY (src_id, dst_id, type)
);
CREATE INDEX IF NOT EXISTS idx_rel_src ON entity_relationships(src_id);
CREATE INDEX IF NOT EXISTS idx_rel_dst ON entity_relationships(dst_id);

CREATE TABLE IF NOT EXISTS entity_evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    value       TEXT DEFAULT '',
    weight      REAL NOT NULL DEFAULT 0,
    source_json TEXT DEFAULT '',
    observed_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_entity ON entity_evidence(entity_id);

CREATE TABLE IF NOT EXISTS entity_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id   TEXT NOT NULL,
    field       TEXT NOT NULL,
    old_value   TEXT DEFAULT '',
    new_value   TEXT DEFAULT '',
    changed_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_entity ON entity_history(entity_id);

CREATE TABLE IF NOT EXISTS entity_cache (
    namespace  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    expires_at REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (namespace, key)
);
"""


class SQLiteStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    # -- entities ---------------------------------------------------------- #

    def save_entity(self, entity: Entity, *, record_history: bool = True) -> None:
        now = time.time()
        payload = json.dumps(entity.to_dict(), ensure_ascii=False, sort_keys=True)
        with self._conn() as conn:
            if record_history:
                self._record_history(conn, entity, now)
            conn.execute(
                """INSERT INTO entities
                   (id,type,value,normalized,confidence,first_seen,last_seen,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     type=excluded.type, value=excluded.value,
                     normalized=excluded.normalized, confidence=excluded.confidence,
                     last_seen=excluded.last_seen, data=excluded.data,
                     updated_at=excluded.updated_at""",
                (entity.id, entity.type.value, entity.value, entity.normalized,
                 entity.confidence, entity.first_seen, entity.last_seen, payload, now))
            conn.executemany(
                "INSERT OR IGNORE INTO entity_aliases (entity_id,alias) VALUES (?,?)",
                [(entity.id, a) for a in entity.aliases])
            for rel in entity.relationships:
                src = rel.source.to_dict() if rel.source else {}
                conn.execute(
                    """INSERT INTO entity_relationships (src_id,dst_id,type,weight,source)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(src_id,dst_id,type) DO UPDATE SET
                         weight=MAX(weight, excluded.weight)""",
                    (entity.id, rel.target_id, rel.type.value, rel.weight,
                     json.dumps(src, ensure_ascii=False)))
            for ev in entity.evidence:
                conn.execute(
                    """INSERT INTO entity_evidence
                       (entity_id,kind,value,weight,source_json,observed_at)
                       VALUES (?,?,?,?,?,?)""",
                    (entity.id, ev.kind, ev.value, ev.weight,
                     json.dumps(ev.source.to_dict() if ev.source else None,
                                ensure_ascii=False),
                     ev.observed_at))

    def _record_history(self, conn: sqlite3.Connection, entity: Entity,
                        now: float) -> None:
        row = conn.execute("SELECT data FROM entities WHERE id=?",
                           (entity.id,)).fetchone()
        if not row:
            return
        try:
            old = json.loads(row["data"])
        except Exception:
            return
        new = entity.to_dict()
        for field in ("value", "normalized", "confidence"):
            if str(old.get(field)) != str(new.get(field)):
                conn.execute(
                    """INSERT INTO entity_history
                       (entity_id,field,old_value,new_value,changed_at)
                       VALUES (?,?,?,?,?)""",
                    (entity.id, field, str(old.get(field)),
                     str(new.get(field)), now))

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM entities WHERE id=?",
                              (entity_id,)).fetchone()
        if not row:
            return None
        return Entity.from_dict(json.loads(row["data"]))

    def find_entities(self, *, entity_type: Optional[str] = None,
                     normalized: Optional[str] = None,
                     limit: int = 100) -> List[Entity]:
        clauses, params = [], []
        if entity_type:
            clauses.append("type=?"); params.append(str(entity_type))
        if normalized:
            clauses.append("normalized=?"); params.append(normalized)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT data FROM entities {where} ORDER BY last_seen DESC LIMIT ?",
                (*params, limit)).fetchall()
        return [Entity.from_dict(json.loads(r["data"])) for r in rows]

    def find_by_alias(self, alias: str, *, limit: int = 100) -> List[Entity]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT e.data FROM entities e
                   JOIN entity_aliases a ON a.entity_id = e.id
                   WHERE a.alias = ? LIMIT ?""", (alias, limit)).fetchall()
        return [Entity.from_dict(json.loads(r["data"])) for r in rows]

    def save_entities(self, entities: List[Entity]) -> int:
        for e in entities:
            self.save_entity(e)
        return len(entities)

    def history_for(self, entity_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT field,old_value,new_value,changed_at
                   FROM entity_history WHERE entity_id=? ORDER BY changed_at""",
                (entity_id,)).fetchall()
        return [dict(r) for r in rows]

    def relationships_for(self, entity_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT src_id,dst_id,type,weight FROM entity_relationships
                   WHERE src_id=? OR dst_id=?""",
                (entity_id, entity_id)).fetchall()
        return [dict(r) for r in rows]

    # -- generic cache ----------------------------------------------------- #

    def cache_set(self, namespace: str, key: str, value: Any,
                 ttl: float = 0.0) -> None:
        expires = time.time() + ttl if ttl > 0 else 0.0
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO entity_cache (namespace,key,value,expires_at)
                   VALUES (?,?,?,?)
                   ON CONFLICT(namespace,key) DO UPDATE SET
                     value=excluded.value, expires_at=excluded.expires_at""",
                (namespace, key, json.dumps(value, ensure_ascii=False), expires))

    def cache_get(self, namespace: str, key: str, default: Any = None) -> Any:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value,expires_at FROM entity_cache WHERE namespace=? AND key=?",
                (namespace, key)).fetchone()
        if not row:
            return default
        if row["expires_at"] and row["expires_at"] < time.time():
            with self._conn() as conn:
                conn.execute("DELETE FROM entity_cache WHERE namespace=? AND key=?",
                            (namespace, key))
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return default

    def stats(self) -> Dict[str, Any]:
        with self._conn() as conn:
            def count(table: str) -> int:
                return conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
            return {
                "db_path": self.db_path,
                "entities": count("entities"),
                "aliases": count("entity_aliases"),
                "relationships": count("entity_relationships"),
                "evidence": count("entity_evidence"),
                "history": count("entity_history"),
                "cache": count("entity_cache"),
            }
