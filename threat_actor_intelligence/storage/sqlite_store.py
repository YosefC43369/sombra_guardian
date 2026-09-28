"""
threat_actor_intelligence.storage.sqlite_store — durable CTI persistence.

Standard-library ``sqlite3`` only, matching the discipline of
``entity_fusion.storage.sqlite_store`` and ``blueteam.store``: CREATE TABLE IF
NOT EXISTS, explicit indexes, a versioned migration table, no ORM, a short-lived
connection per operation (WAL) so the store is safe under async callers.

Every object is stored twice-over: the full ``to_dict()`` as a JSON ``data``
blob (lossless), plus the scalar columns that need indexing for query. Evidence,
aliases, relationships and timeline events are normalized into their own tables
so they can be counted, joined and deduplicated.

Schema (spec DATABASE TABLES):
  actors, campaigns, malware_families, ioc, reports, aliases, techniques,
  software, victimology, relationships, evidence, timeline
plus: tactics, mitigations, capec, provider_state (incremental ingestion),
schema_migrations, kv (generic).

Batch writes go through ``save_*`` helpers that reuse one transaction; large
result sets stream via generator-returning ``iter_*`` methods.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from ..models.threat_actor import ThreatActor
from ..models.campaign import Campaign
from ..models.malware_family import MalwareFamily
from ..models.infrastructure import Infrastructure
from ..models.ioc import IOC
from ..models.report import Report
from ..models.technique import Technique, Tactic, Mitigation, CAPECPattern
from ..models.software import Software
from ..models.victimology import Victimology, VictimObservation
from ..models.relation import Relationship

DEFAULT_DB_PATH = "threat_actor_intelligence.db"
SCHEMA_VERSION = 1


_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS actors (
    actor_id      TEXT PRIMARY KEY,
    canonical_name TEXT NOT NULL,
    actor_type    TEXT NOT NULL DEFAULT 'unknown',
    attack_group_id TEXT DEFAULT '',
    confidence    REAL NOT NULL DEFAULT 0,
    first_seen    REAL NOT NULL DEFAULT 0,
    last_seen     REAL NOT NULL DEFAULT 0,
    data          TEXT NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actors_name ON actors(canonical_name);
CREATE INDEX IF NOT EXISTS idx_actors_type ON actors(actor_type);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id   TEXT PRIMARY KEY,
    campaign_name TEXT NOT NULL,
    confidence    REAL NOT NULL DEFAULT 0,
    first_observed REAL NOT NULL DEFAULT 0,
    last_observed REAL NOT NULL DEFAULT 0,
    data          TEXT NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_campaigns_name ON campaigns(campaign_name);

CREATE TABLE IF NOT EXISTS malware_families (
    family_id     TEXT PRIMARY KEY,
    family_name   TEXT NOT NULL,
    category      TEXT DEFAULT '',
    attack_software_id TEXT DEFAULT '',
    confidence    REAL NOT NULL DEFAULT 0,
    first_seen    REAL NOT NULL DEFAULT 0,
    last_seen     REAL NOT NULL DEFAULT 0,
    data          TEXT NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_family_name ON malware_families(family_name);

CREATE TABLE IF NOT EXISTS infrastructure (
    infra_id      TEXT PRIMARY KEY,
    infra_type    TEXT NOT NULL,
    value         TEXT NOT NULL,
    asn           TEXT DEFAULT '',
    country       TEXT DEFAULT '',
    confidence    REAL NOT NULL DEFAULT 0,
    first_seen    REAL NOT NULL DEFAULT 0,
    last_seen     REAL NOT NULL DEFAULT 0,
    data          TEXT NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_infra_value ON infrastructure(value);
CREATE INDEX IF NOT EXISTS idx_infra_type ON infrastructure(infra_type);

CREATE TABLE IF NOT EXISTS ioc (
    ioc_id     TEXT PRIMARY KEY,
    ioc_type   TEXT NOT NULL,
    value      TEXT NOT NULL,
    malware    TEXT DEFAULT '',
    campaign   TEXT DEFAULT '',
    actor      TEXT DEFAULT '',
    first_seen REAL NOT NULL DEFAULT 0,
    last_seen  REAL NOT NULL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc(ioc_type);

CREATE TABLE IF NOT EXISTS reports (
    report_id  TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    url        TEXT DEFAULT '',
    source     TEXT DEFAULT '',
    vendor     TEXT DEFAULT '',
    published_at REAL NOT NULL DEFAULT 0,
    content_hash TEXT DEFAULT '',
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_url ON reports(url);
CREATE INDEX IF NOT EXISTS idx_reports_hash ON reports(content_hash);
CREATE INDEX IF NOT EXISTS idx_reports_source ON reports(source);

CREATE TABLE IF NOT EXISTS aliases (
    object_type TEXT NOT NULL,       -- actor | campaign | malware
    object_id   TEXT NOT NULL,
    alias       TEXT NOT NULL,       -- normalized
    display     TEXT DEFAULT '',
    source      TEXT DEFAULT '',
    kind        TEXT DEFAULT '',
    PRIMARY KEY (object_type, object_id, alias)
);
CREATE INDEX IF NOT EXISTS idx_alias_alias ON aliases(alias);

CREATE TABLE IF NOT EXISTS techniques (
    technique_id TEXT PRIMARY KEY,
    name        TEXT DEFAULT '',
    domain      TEXT DEFAULT 'enterprise-attack',
    is_subtechnique INTEGER DEFAULT 0,
    parent_id   TEXT DEFAULT '',
    data        TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tech_parent ON techniques(parent_id);

CREATE TABLE IF NOT EXISTS tactics (
    tactic_id  TEXT PRIMARY KEY,
    short_name TEXT DEFAULT '',
    name       TEXT DEFAULT '',
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS mitigations (
    mitigation_id TEXT PRIMARY KEY,
    name        TEXT DEFAULT '',
    data        TEXT NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS capec (
    capec_id   TEXT PRIMARY KEY,
    name       TEXT DEFAULT '',
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS software (
    software_id TEXT PRIMARY KEY,
    name       TEXT DEFAULT '',
    software_type TEXT DEFAULT 'unknown',
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_software_name ON software(name);

CREATE TABLE IF NOT EXISTS victimology (
    id          TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,       -- actor | campaign
    subject_id  TEXT NOT NULL,
    country     TEXT DEFAULT '',
    sector      TEXT DEFAULT '',
    data        TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_victim_subject ON victimology(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_victim_country ON victimology(country);
CREATE INDEX IF NOT EXISTS idx_victim_sector ON victimology(sector);

CREATE TABLE IF NOT EXISTS relationships (
    rel_id     TEXT PRIMARY KEY,
    src_type   TEXT NOT NULL,
    src_id     TEXT NOT NULL,
    rel_type   TEXT NOT NULL,
    dst_type   TEXT NOT NULL,
    dst_id     TEXT NOT NULL,
    weight     REAL NOT NULL DEFAULT 1.0,
    confidence REAL NOT NULL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rel_src ON relationships(src_type, src_id);
CREATE INDEX IF NOT EXISTS idx_rel_dst ON relationships(dst_type, dst_id);
CREATE INDEX IF NOT EXISTS idx_rel_type ON relationships(rel_type);

CREATE TABLE IF NOT EXISTS evidence (
    ref_id      TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id   TEXT NOT NULL,
    provider    TEXT DEFAULT '',
    source_url  TEXT DEFAULT '',
    observed_at REAL NOT NULL DEFAULT 0,
    data        TEXT NOT NULL,
    PRIMARY KEY (object_type, object_id, ref_id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_object ON evidence(object_type, object_id);
CREATE INDEX IF NOT EXISTS idx_evidence_provider ON evidence(provider);

CREATE TABLE IF NOT EXISTS timeline (
    event_id    TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id  TEXT NOT NULL,
    at          REAL NOT NULL,
    kind        TEXT NOT NULL,
    label       TEXT DEFAULT '',
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timeline_subject ON timeline(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_timeline_at ON timeline(at);

CREATE TABLE IF NOT EXISTS provider_state (
    provider    TEXT NOT NULL,
    resource    TEXT NOT NULL,
    etag        TEXT DEFAULT '',
    last_modified TEXT DEFAULT '',
    content_hash TEXT DEFAULT '',
    provider_version TEXT DEFAULT '',
    fetched_at  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (provider, resource)
);

CREATE TABLE IF NOT EXISTS kv (
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

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self) -> None:
        with self._tx() as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT MAX(version) v FROM schema_migrations").fetchone()
            if not row or row["v"] is None:
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) "
                    "VALUES (?,?)", (SCHEMA_VERSION, time.time()))

    def schema_version(self) -> int:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT MAX(version) v FROM schema_migrations").fetchone()
        return int(row["v"]) if row and row["v"] is not None else 0

    # -- evidence + aliases (shared helpers) ------------------------------- #

    def _save_evidence(self, conn: sqlite3.Connection, object_type: str,
                       object_id: str, refs: List[Dict[str, Any]]) -> None:
        for ref in refs:
            conn.execute(
                """INSERT INTO evidence
                   (ref_id,object_type,object_id,provider,source_url,observed_at,data)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(object_type,object_id,ref_id) DO UPDATE SET
                     observed_at=MAX(observed_at, excluded.observed_at),
                     data=excluded.data""",
                (ref.get("ref_id", ""), object_type, object_id,
                 ref.get("provider", ""), ref.get("source_url", ""),
                 float(ref.get("observed_at", 0) or 0),
                 json.dumps(ref, ensure_ascii=False)))

    def _save_aliases(self, conn: sqlite3.Connection, object_type: str,
                      object_id: str, aliases: List[Dict[str, Any]]) -> None:
        for a in aliases:
            conn.execute(
                """INSERT OR IGNORE INTO aliases
                   (object_type,object_id,alias,display,source,kind)
                   VALUES (?,?,?,?,?,?)""",
                (object_type, object_id, a.get("normalized", "").strip(),
                 a.get("name", ""), a.get("source", ""), a.get("kind", "")))

    def _save_victimology(self, conn: sqlite3.Connection, subject_type: str,
                          subject_id: str, victimology: Dict[str, Any]) -> None:
        for obs in victimology.get("observations", []) or []:
            conn.execute(
                """INSERT INTO victimology
                   (id,subject_type,subject_id,country,sector,data,updated_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET data=excluded.data,
                     updated_at=excluded.updated_at""",
                (obs.get("id", ""), subject_type, subject_id,
                 obs.get("country", ""), obs.get("sector", ""),
                 json.dumps(obs, ensure_ascii=False), time.time()))

    # -- actors ------------------------------------------------------------ #

    def save_actor(self, actor: ThreatActor) -> None:
        d = actor.to_dict()
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO actors
                   (actor_id,canonical_name,actor_type,attack_group_id,confidence,
                    first_seen,last_seen,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(actor_id) DO UPDATE SET
                     canonical_name=excluded.canonical_name,
                     actor_type=excluded.actor_type,
                     attack_group_id=excluded.attack_group_id,
                     confidence=excluded.confidence, last_seen=excluded.last_seen,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (actor.actor_id, actor.canonical_name, actor.actor_type.value,
                 actor.attack_group_id,
                 (actor.confidence.score if actor.confidence else 0.0),
                 actor.first_seen, actor.last_seen,
                 json.dumps(d, ensure_ascii=False), now))
            self._save_aliases(conn, "actor", actor.actor_id, d["aliases"])
            self._save_evidence(conn, "actor", actor.actor_id, d["evidence"])
            self._save_victimology(conn, "actor", actor.actor_id, d["victimology"])

    def get_actor(self, actor_id: str) -> Optional[ThreatActor]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM actors WHERE actor_id=?",
                               (actor_id,)).fetchone()
        return ThreatActor.from_dict(json.loads(row["data"])) if row else None

    def find_actor_by_name(self, name: str) -> Optional[ThreatActor]:
        norm = (name or "").strip().lower()
        with self._tx() as conn:
            row = conn.execute(
                "SELECT data FROM actors WHERE LOWER(canonical_name)=?",
                (norm,)).fetchone()
            if row:
                return ThreatActor.from_dict(json.loads(row["data"]))
            arow = conn.execute(
                """SELECT a.object_id FROM aliases a
                   WHERE a.object_type='actor' AND a.alias=? LIMIT 1""",
                (norm,)).fetchone()
            if arow:
                r2 = conn.execute("SELECT data FROM actors WHERE actor_id=?",
                                  (arow["object_id"],)).fetchone()
                if r2:
                    return ThreatActor.from_dict(json.loads(r2["data"]))
        return None

    def find_actors_by_alias(self, alias: str) -> List[ThreatActor]:
        norm = (alias or "").strip().lower()
        with self._tx() as conn:
            rows = conn.execute(
                """SELECT DISTINCT ac.data FROM actors ac
                   JOIN aliases al ON al.object_id = ac.actor_id
                   WHERE al.object_type='actor' AND al.alias=?""",
                (norm,)).fetchall()
        return [ThreatActor.from_dict(json.loads(r["data"])) for r in rows]

    def iter_actors(self, *, limit: int = 0) -> Iterator[ThreatActor]:
        q = "SELECT data FROM actors ORDER BY last_seen DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q):
                yield ThreatActor.from_dict(json.loads(row["data"]))

    def list_actors(self, *, limit: int = 100) -> List[ThreatActor]:
        return list(self.iter_actors(limit=limit))

    # -- campaigns --------------------------------------------------------- #

    def save_campaign(self, c: Campaign) -> None:
        d = c.to_dict()
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO campaigns
                   (campaign_id,campaign_name,confidence,first_observed,
                    last_observed,data,updated_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(campaign_id) DO UPDATE SET
                     campaign_name=excluded.campaign_name,
                     confidence=excluded.confidence,
                     last_observed=excluded.last_observed,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (c.campaign_id, c.campaign_name,
                 (c.confidence.score if c.confidence else 0.0),
                 c.first_observed, c.last_observed,
                 json.dumps(d, ensure_ascii=False), now))
            self._save_aliases(conn, "campaign", c.campaign_id, d["aliases"])
            self._save_evidence(conn, "campaign", c.campaign_id, d["evidence"])
            self._save_victimology(conn, "campaign", c.campaign_id, d["victimology"])

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM campaigns WHERE campaign_id=?",
                               (campaign_id,)).fetchone()
        return Campaign.from_dict(json.loads(row["data"])) if row else None

    def find_campaign_by_name(self, name: str) -> Optional[Campaign]:
        norm = (name or "").strip().lower()
        with self._tx() as conn:
            row = conn.execute(
                "SELECT data FROM campaigns WHERE LOWER(campaign_name)=?",
                (norm,)).fetchone()
        return Campaign.from_dict(json.loads(row["data"])) if row else None

    def iter_campaigns(self, *, limit: int = 0) -> Iterator[Campaign]:
        q = "SELECT data FROM campaigns ORDER BY last_observed DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q):
                yield Campaign.from_dict(json.loads(row["data"]))

    def list_campaigns(self, *, limit: int = 100) -> List[Campaign]:
        return list(self.iter_campaigns(limit=limit))

    # -- malware families -------------------------------------------------- #

    def save_family(self, m: MalwareFamily) -> None:
        d = m.to_dict()
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO malware_families
                   (family_id,family_name,category,attack_software_id,confidence,
                    first_seen,last_seen,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(family_id) DO UPDATE SET
                     family_name=excluded.family_name, category=excluded.category,
                     attack_software_id=excluded.attack_software_id,
                     confidence=excluded.confidence, last_seen=excluded.last_seen,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (m.family_id, m.family_name, m.category, m.attack_software_id,
                 (m.confidence.score if m.confidence else 0.0),
                 m.first_seen, m.last_seen, json.dumps(d, ensure_ascii=False), now))
            self._save_aliases(conn, "malware", m.family_id, d["aliases"])
            self._save_evidence(conn, "malware", m.family_id, d["evidence"])

    def get_family(self, family_id: str) -> Optional[MalwareFamily]:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT data FROM malware_families WHERE family_id=?",
                (family_id,)).fetchone()
        return MalwareFamily.from_dict(json.loads(row["data"])) if row else None

    def find_family_by_name(self, name: str) -> Optional[MalwareFamily]:
        norm = (name or "").strip().lower()
        with self._tx() as conn:
            row = conn.execute(
                "SELECT data FROM malware_families WHERE LOWER(family_name)=?",
                (norm,)).fetchone()
            if row:
                return MalwareFamily.from_dict(json.loads(row["data"]))
            arow = conn.execute(
                "SELECT object_id FROM aliases WHERE object_type='malware' AND alias=? "
                "LIMIT 1", (norm,)).fetchone()
            if arow:
                r2 = conn.execute("SELECT data FROM malware_families WHERE family_id=?",
                                  (arow["object_id"],)).fetchone()
                if r2:
                    return MalwareFamily.from_dict(json.loads(r2["data"]))
        return None

    def iter_families(self, *, limit: int = 0) -> Iterator[MalwareFamily]:
        q = "SELECT data FROM malware_families ORDER BY last_seen DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q):
                yield MalwareFamily.from_dict(json.loads(row["data"]))

    def list_families(self, *, limit: int = 100) -> List[MalwareFamily]:
        return list(self.iter_families(limit=limit))

    # -- infrastructure ---------------------------------------------------- #

    def save_infrastructure(self, node: Infrastructure) -> None:
        d = node.to_dict()
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO infrastructure
                   (infra_id,infra_type,value,asn,country,confidence,
                    first_seen,last_seen,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(infra_id) DO UPDATE SET
                     asn=excluded.asn, country=excluded.country,
                     confidence=excluded.confidence, last_seen=excluded.last_seen,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (node.infra_id, node.infra_type.value, node.value, node.asn,
                 node.country, (node.confidence.score if node.confidence else 0.0),
                 node.first_seen, node.last_seen,
                 json.dumps(d, ensure_ascii=False), now))
            self._save_evidence(conn, "infrastructure", node.infra_id, d["evidence"])

    def get_infrastructure(self, infra_id: str) -> Optional[Infrastructure]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM infrastructure WHERE infra_id=?",
                               (infra_id,)).fetchone()
        return Infrastructure.from_dict(json.loads(row["data"])) if row else None

    def find_infrastructure_by_value(self, value: str) -> List[Infrastructure]:
        with self._tx() as conn:
            rows = conn.execute("SELECT data FROM infrastructure WHERE value=?",
                                (value,)).fetchall()
        return [Infrastructure.from_dict(json.loads(r["data"])) for r in rows]

    def iter_infrastructure(self, *, limit: int = 0) -> Iterator[Infrastructure]:
        q = "SELECT data FROM infrastructure ORDER BY last_seen DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q):
                yield Infrastructure.from_dict(json.loads(row["data"]))

    # -- iocs -------------------------------------------------------------- #

    def save_ioc(self, ioc: IOC) -> None:
        d = ioc.to_dict()
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO ioc
                   (ioc_id,ioc_type,value,malware,campaign,actor,
                    first_seen,last_seen,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ioc_id) DO UPDATE SET
                     malware=excluded.malware, campaign=excluded.campaign,
                     actor=excluded.actor, last_seen=excluded.last_seen,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (ioc.id, ioc.ioc_type.value, ioc.value, ioc.malware, ioc.campaign,
                 ioc.actor, ioc.first_seen, ioc.last_seen,
                 json.dumps(d, ensure_ascii=False), now))
            self._save_evidence(conn, "ioc", ioc.id, d["evidence"])

    def save_iocs(self, iocs: List[IOC]) -> int:
        """Batch write in one transaction."""
        now = time.time()
        rows = 0
        with self._tx() as conn:
            for ioc in iocs:
                d = ioc.to_dict()
                conn.execute(
                    """INSERT INTO ioc
                       (ioc_id,ioc_type,value,malware,campaign,actor,
                        first_seen,last_seen,data,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(ioc_id) DO UPDATE SET
                         last_seen=excluded.last_seen, data=excluded.data,
                         updated_at=excluded.updated_at""",
                    (ioc.id, ioc.ioc_type.value, ioc.value, ioc.malware,
                     ioc.campaign, ioc.actor, ioc.first_seen, ioc.last_seen,
                     json.dumps(d, ensure_ascii=False), now))
                self._save_evidence(conn, "ioc", ioc.id, d["evidence"])
                rows += 1
        return rows

    def get_ioc(self, ioc_id: str) -> Optional[IOC]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM ioc WHERE ioc_id=?",
                               (ioc_id,)).fetchone()
        return IOC.from_dict(json.loads(row["data"])) if row else None

    def find_ioc_by_value(self, value: str) -> Optional[IOC]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM ioc WHERE value=? LIMIT 1",
                               (value,)).fetchone()
        return IOC.from_dict(json.loads(row["data"])) if row else None

    def iter_iocs(self, *, ioc_type: str = "", limit: int = 0) -> Iterator[IOC]:
        q = "SELECT data FROM ioc"
        params: List[Any] = []
        if ioc_type:
            q += " WHERE ioc_type=?"
            params.append(ioc_type)
        q += " ORDER BY last_seen DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q, params):
                yield IOC.from_dict(json.loads(row["data"]))

    # -- reports ----------------------------------------------------------- #

    def save_report(self, r: Report) -> None:
        d = r.to_dict()
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO reports
                   (report_id,title,url,source,vendor,published_at,content_hash,
                    data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(report_id) DO UPDATE SET
                     title=excluded.title, content_hash=excluded.content_hash,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (r.report_id, r.title, r.url, r.source, r.vendor, r.published_at,
                 r.content_hash, json.dumps(d, ensure_ascii=False), now))

    def get_report(self, report_id: str) -> Optional[Report]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM reports WHERE report_id=?",
                               (report_id,)).fetchone()
        return Report.from_dict(json.loads(row["data"])) if row else None

    def report_exists(self, *, url: str = "", content_hash: str = "") -> bool:
        with self._tx() as conn:
            if content_hash:
                row = conn.execute(
                    "SELECT 1 FROM reports WHERE content_hash=? LIMIT 1",
                    (content_hash,)).fetchone()
                if row:
                    return True
            if url:
                row = conn.execute("SELECT 1 FROM reports WHERE url=? LIMIT 1",
                                   (url,)).fetchone()
                return bool(row)
        return False

    def iter_reports(self, *, source: str = "", limit: int = 0) -> Iterator[Report]:
        q = "SELECT data FROM reports"
        params: List[Any] = []
        if source:
            q += " WHERE source=?"
            params.append(source)
        q += " ORDER BY published_at DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._tx() as conn:
            for row in conn.execute(q, params):
                yield Report.from_dict(json.loads(row["data"]))

    # -- MITRE reference objects ------------------------------------------ #

    def save_technique(self, t: Technique) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO techniques
                   (technique_id,name,domain,is_subtechnique,parent_id,data,updated_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(technique_id) DO UPDATE SET
                     name=excluded.name, data=excluded.data,
                     updated_at=excluded.updated_at""",
                (t.technique_id, t.name, t.domain.value, int(t.is_subtechnique),
                 t.parent_id, json.dumps(t.to_dict(), ensure_ascii=False), time.time()))

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM techniques WHERE technique_id=?",
                               (technique_id,)).fetchone()
        return Technique.from_dict(json.loads(row["data"])) if row else None

    def iter_techniques(self) -> Iterator[Technique]:
        with self._tx() as conn:
            for row in conn.execute("SELECT data FROM techniques ORDER BY technique_id"):
                yield Technique.from_dict(json.loads(row["data"]))

    def save_tactic(self, t: Tactic) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO tactics (tactic_id,short_name,name,data,updated_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(tactic_id) DO UPDATE SET data=excluded.data,
                     updated_at=excluded.updated_at""",
                (t.tactic_id, t.short_name, t.name,
                 json.dumps(t.to_dict(), ensure_ascii=False), time.time()))

    def save_mitigation(self, m: Mitigation) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO mitigations (mitigation_id,name,data,updated_at)
                   VALUES (?,?,?,?)
                   ON CONFLICT(mitigation_id) DO UPDATE SET data=excluded.data,
                     updated_at=excluded.updated_at""",
                (m.mitigation_id, m.name,
                 json.dumps(m.to_dict(), ensure_ascii=False), time.time()))

    def save_capec(self, c: CAPECPattern) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO capec (capec_id,name,data,updated_at)
                   VALUES (?,?,?,?)
                   ON CONFLICT(capec_id) DO UPDATE SET data=excluded.data,
                     updated_at=excluded.updated_at""",
                (c.capec_id, c.name,
                 json.dumps(c.to_dict(), ensure_ascii=False), time.time()))

    def get_capec(self, capec_id: str) -> Optional[CAPECPattern]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM capec WHERE capec_id=?",
                               (capec_id,)).fetchone()
        return CAPECPattern.from_dict(json.loads(row["data"])) if row else None

    def save_software(self, s: Software) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO software (software_id,name,software_type,data,updated_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(software_id) DO UPDATE SET name=excluded.name,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (s.software_id, s.name, s.software_type.value,
                 json.dumps(s.to_dict(), ensure_ascii=False), time.time()))

    def get_software(self, software_id: str) -> Optional[Software]:
        with self._tx() as conn:
            row = conn.execute("SELECT data FROM software WHERE software_id=?",
                               (software_id,)).fetchone()
        return Software.from_dict(json.loads(row["data"])) if row else None

    # -- relationships ----------------------------------------------------- #

    def save_relationship(self, rel: Relationship) -> None:
        d = rel.to_dict()
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO relationships
                   (rel_id,src_type,src_id,rel_type,dst_type,dst_id,weight,
                    confidence,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(rel_id) DO UPDATE SET
                     weight=MAX(weight, excluded.weight),
                     confidence=excluded.confidence, data=excluded.data,
                     updated_at=excluded.updated_at""",
                (rel.id, rel.src_type.value, rel.src_id, rel.rel_type.value,
                 rel.dst_type.value, rel.dst_id, rel.weight, rel.score,
                 json.dumps(d, ensure_ascii=False), time.time()))

    def save_relationships(self, rels: List[Relationship]) -> int:
        with self._tx() as conn:
            for rel in rels:
                conn.execute(
                    """INSERT INTO relationships
                       (rel_id,src_type,src_id,rel_type,dst_type,dst_id,weight,
                        confidence,data,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(rel_id) DO UPDATE SET
                         weight=MAX(weight, excluded.weight),
                         confidence=excluded.confidence, data=excluded.data,
                         updated_at=excluded.updated_at""",
                    (rel.id, rel.src_type.value, rel.src_id, rel.rel_type.value,
                     rel.dst_type.value, rel.dst_id, rel.weight, rel.score,
                     json.dumps(rel.to_dict(), ensure_ascii=False), time.time()))
        return len(rels)

    def relationships_for(self, object_type: str, object_id: str
                          ) -> List[Relationship]:
        with self._tx() as conn:
            rows = conn.execute(
                """SELECT data FROM relationships
                   WHERE (src_type=? AND src_id=?) OR (dst_type=? AND dst_id=?)""",
                (object_type, object_id, object_type, object_id)).fetchall()
        return [Relationship.from_dict(json.loads(r["data"])) for r in rows]

    def iter_relationships(self, *, rel_type: str = "") -> Iterator[Relationship]:
        q = "SELECT data FROM relationships"
        params: List[Any] = []
        if rel_type:
            q += " WHERE rel_type=?"
            params.append(rel_type)
        with self._tx() as conn:
            for row in conn.execute(q, params):
                yield Relationship.from_dict(json.loads(row["data"]))

    # -- timeline ---------------------------------------------------------- #

    def save_timeline_event(self, subject_type: str, subject_id: str,
                            event: Dict[str, Any]) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO timeline
                   (event_id,subject_type,subject_id,at,kind,label,data)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(event_id) DO UPDATE SET data=excluded.data""",
                (event.get("event_id", ""), subject_type, subject_id,
                 float(event.get("at", 0) or 0), event.get("kind", ""),
                 event.get("label", ""), json.dumps(event, ensure_ascii=False)))

    def timeline_for(self, subject_type: str, subject_id: str
                     ) -> List[Dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute(
                """SELECT data FROM timeline
                   WHERE subject_type=? AND subject_id=? ORDER BY at""",
                (subject_type, subject_id)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    # -- victimology queries ---------------------------------------------- #

    def victimology_for(self, subject_type: str, subject_id: str) -> Victimology:
        with self._tx() as conn:
            rows = conn.execute(
                """SELECT data FROM victimology
                   WHERE subject_type=? AND subject_id=?""",
                (subject_type, subject_id)).fetchall()
        v = Victimology(subject_id=subject_id)
        for r in rows:
            v.add(VictimObservation.from_dict(json.loads(r["data"])))
        return v

    # -- provider incremental-ingestion state ----------------------------- #

    def get_provider_state(self, provider: str, resource: str) -> Dict[str, Any]:
        with self._tx() as conn:
            row = conn.execute(
                """SELECT etag,last_modified,content_hash,provider_version,fetched_at
                   FROM provider_state WHERE provider=? AND resource=?""",
                (provider, resource)).fetchone()
        return dict(row) if row else {}

    def set_provider_state(self, provider: str, resource: str, *, etag: str = "",
                           last_modified: str = "", content_hash: str = "",
                           provider_version: str = "") -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO provider_state
                   (provider,resource,etag,last_modified,content_hash,
                    provider_version,fetched_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(provider,resource) DO UPDATE SET
                     etag=excluded.etag, last_modified=excluded.last_modified,
                     content_hash=excluded.content_hash,
                     provider_version=excluded.provider_version,
                     fetched_at=excluded.fetched_at""",
                (provider, resource, etag, last_modified, content_hash,
                 provider_version, time.time()))

    # -- generic kv -------------------------------------------------------- #

    def kv_set(self, namespace: str, key: str, value: Any, ttl: float = 0) -> None:
        expires = time.time() + ttl if ttl > 0 else 0
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO kv (namespace,key,value,expires_at)
                   VALUES (?,?,?,?)
                   ON CONFLICT(namespace,key) DO UPDATE SET value=excluded.value,
                     expires_at=excluded.expires_at""",
                (namespace, key, json.dumps(value, ensure_ascii=False), expires))

    def kv_get(self, namespace: str, key: str, default: Any = None) -> Any:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT value,expires_at FROM kv WHERE namespace=? AND key=?",
                (namespace, key)).fetchone()
        if not row:
            return default
        if row["expires_at"] and row["expires_at"] < time.time():
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return default

    # -- stats ------------------------------------------------------------- #

    def stats(self) -> Dict[str, Any]:
        with self._tx() as conn:
            def count(t: str) -> int:
                return conn.execute(f"SELECT COUNT(*) c FROM {t}").fetchone()["c"]
            return {
                "db_path": self.db_path, "schema_version": self.schema_version(),
                "actors": count("actors"), "campaigns": count("campaigns"),
                "malware_families": count("malware_families"),
                "infrastructure": count("infrastructure"), "ioc": count("ioc"),
                "reports": count("reports"), "aliases": count("aliases"),
                "techniques": count("techniques"), "tactics": count("tactics"),
                "mitigations": count("mitigations"), "capec": count("capec"),
                "software": count("software"), "victimology": count("victimology"),
                "relationships": count("relationships"),
                "evidence": count("evidence"), "timeline": count("timeline"),
            }


__all__ = ["SQLiteStore", "DEFAULT_DB_PATH", "SCHEMA_VERSION"]
