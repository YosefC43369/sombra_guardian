"""
news_intelligence.storage.sqlite_store — durable news-intelligence persistence.

Standard-library ``sqlite3`` only, matching the discipline of
``threat_actor_intelligence.storage.sqlite_store`` and
``entity_fusion.storage.sqlite_store``: CREATE TABLE IF NOT EXISTS, explicit
indexes, a versioned migration table, no ORM, a short-lived WAL connection per
operation so the store is safe under async callers.

Every object is stored twice-over: the lossless ``to_dict()`` JSON ``data`` blob,
plus the scalar columns query needs for indexing. Entity mentions, IOCs,
relationships, timeline events and evidence normalize into their own tables so they
can be counted, joined and deduplicated.

Schema (spec DATABASE TABLES):
  news_articles, news_sources, news_entities, news_iocs, news_campaigns,
  news_relationships, news_topics, news_clusters, news_timeline, news_reports,
  news_evidence
plus: news_feeds, provider_state (incremental ingestion), schema_migrations,
kv (generic key/value).
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from ..models.article import Article
from ..models.source import NewsSource
from ..models.feed import Feed
from ..models.entity import EntityMention
from ..models.topic import Topic, Cluster, NewsEvent
from ..models.report import NewsReport

DEFAULT_DB_PATH = "news_intelligence.db"
SCHEMA_VERSION = 1


_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS news_sources (
    source_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    category   TEXT DEFAULT '',
    reliability_class TEXT DEFAULT '',
    country    TEXT DEFAULT '',
    language   TEXT DEFAULT '',
    domain     TEXT DEFAULT '',
    enabled    INTEGER DEFAULT 1,
    last_ingested REAL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_src_domain ON news_sources(domain);
CREATE INDEX IF NOT EXISTS idx_src_category ON news_sources(category);

CREATE TABLE IF NOT EXISTS news_feeds (
    feed_id    TEXT PRIMARY KEY,
    url        TEXT NOT NULL,
    source_id  TEXT DEFAULT '',
    provider   TEXT DEFAULT '',
    enabled    INTEGER DEFAULT 1,
    last_polled REAL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feed_url ON news_feeds(url);
CREATE INDEX IF NOT EXISTS idx_feed_source ON news_feeds(source_id);

CREATE TABLE IF NOT EXISTS news_articles (
    article_id TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    url        TEXT DEFAULT '',
    canonical_url TEXT DEFAULT '',
    source_id  TEXT DEFAULT '',
    source_name TEXT DEFAULT '',
    source_domain TEXT DEFAULT '',
    language   TEXT DEFAULT '',
    publication_date REAL DEFAULT 0,
    ingestion_date REAL DEFAULT 0,
    content_hash TEXT DEFAULT '',
    simhash    TEXT DEFAULT '',
    duplicate_of TEXT DEFAULT '',
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_art_hash ON news_articles(content_hash);
CREATE INDEX IF NOT EXISTS idx_art_canon ON news_articles(canonical_url);
CREATE INDEX IF NOT EXISTS idx_art_pub ON news_articles(publication_date);
CREATE INDEX IF NOT EXISTS idx_art_domain ON news_articles(source_domain);
CREATE INDEX IF NOT EXISTS idx_art_dup ON news_articles(duplicate_of);

CREATE TABLE IF NOT EXISTS news_entities (
    entity_key  TEXT NOT NULL,
    article_id  TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    surface     TEXT DEFAULT '',
    extractor   TEXT DEFAULT '',
    weight      REAL DEFAULT 1,
    data        TEXT NOT NULL,
    PRIMARY KEY (entity_key, article_id)
);
CREATE INDEX IF NOT EXISTS idx_ent_value ON news_entities(value);
CREATE INDEX IF NOT EXISTS idx_ent_type ON news_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_ent_article ON news_entities(article_id);
CREATE INDEX IF NOT EXISTS idx_ent_key ON news_entities(entity_key);

CREATE TABLE IF NOT EXISTS news_iocs (
    ioc_key    TEXT NOT NULL,
    article_id TEXT NOT NULL,
    ioc_type   TEXT NOT NULL,
    value      TEXT NOT NULL,
    first_seen REAL DEFAULT 0,
    last_seen  REAL DEFAULT 0,
    PRIMARY KEY (ioc_key, article_id)
);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON news_iocs(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON news_iocs(ioc_type);

CREATE TABLE IF NOT EXISTS news_campaigns (
    campaign_key TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    first_reported REAL DEFAULT 0,
    last_reported REAL DEFAULT 0,
    mention_count INTEGER DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_camp_name ON news_campaigns(name);

CREATE TABLE IF NOT EXISTS news_relationships (
    rel_id     TEXT PRIMARY KEY,
    src_type   TEXT NOT NULL,
    src_key    TEXT NOT NULL,
    dst_type   TEXT NOT NULL,
    dst_key    TEXT NOT NULL,
    rel_type   TEXT NOT NULL,
    weight     REAL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rel_src ON news_relationships(src_key);
CREATE INDEX IF NOT EXISTS idx_rel_dst ON news_relationships(dst_key);
CREATE INDEX IF NOT EXISTS idx_rel_type ON news_relationships(rel_type);

CREATE TABLE IF NOT EXISTS news_topics (
    topic_id   TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    first_seen REAL DEFAULT 0,
    last_seen  REAL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_topic_label ON news_topics(label);

CREATE TABLE IF NOT EXISTS news_clusters (
    cluster_id TEXT PRIMARY KEY,
    kind       TEXT DEFAULT 'topic',
    label      TEXT DEFAULT '',
    size       INTEGER DEFAULT 0,
    first_seen REAL DEFAULT 0,
    last_seen  REAL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clu_kind ON news_clusters(kind);

CREATE TABLE IF NOT EXISTS news_timeline (
    event_id   TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    subject_type TEXT DEFAULT '',
    ts         REAL DEFAULT 0,
    article_id TEXT DEFAULT '',
    label      TEXT DEFAULT '',
    data       TEXT NOT NULL,
    PRIMARY KEY (event_id, subject_key)
);
CREATE INDEX IF NOT EXISTS idx_tl_subject ON news_timeline(subject_key);
CREATE INDEX IF NOT EXISTS idx_tl_ts ON news_timeline(ts);

CREATE TABLE IF NOT EXISTS news_reports (
    report_id  TEXT PRIMARY KEY,
    report_type TEXT DEFAULT '',
    subject    TEXT DEFAULT '',
    generated_at REAL DEFAULT 0,
    data       TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rep_type ON news_reports(report_type);

CREATE TABLE IF NOT EXISTS news_evidence (
    ref_id     TEXT NOT NULL,
    owner_key  TEXT NOT NULL,
    provider   TEXT DEFAULT '',
    source_url TEXT DEFAULT '',
    observed_at REAL DEFAULT 0,
    data       TEXT NOT NULL,
    PRIMARY KEY (ref_id, owner_key)
);
CREATE INDEX IF NOT EXISTS idx_ev_owner ON news_evidence(owner_key);

CREATE TABLE IF NOT EXISTS provider_state (
    provider   TEXT NOT NULL,
    resource   TEXT NOT NULL,
    etag       TEXT DEFAULT '',
    last_modified TEXT DEFAULT '',
    last_run   REAL DEFAULT 0,
    cursor     TEXT DEFAULT '',
    PRIMARY KEY (provider, resource)
);

CREATE TABLE IF NOT EXISTS kv (
    namespace TEXT NOT NULL,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (namespace, key)
);
"""


class SQLiteStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute(
                "SELECT MAX(version) AS v FROM schema_migrations").fetchone()
            if not row or row["v"] is None:
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?,?)",
                    (SCHEMA_VERSION, time.time()))

    def schema_version(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT MAX(version) AS v FROM schema_migrations").fetchone()
            return int(row["v"]) if row and row["v"] is not None else 0

    # ------------------------------------------------------------------ #
    # sources
    # ------------------------------------------------------------------ #
    def save_source(self, source: NewsSource) -> None:
        with self._conn() as conn:
            self._save_source(conn, source)

    def save_sources(self, sources: List[NewsSource]) -> int:
        with self._conn() as conn:
            for s in sources:
                self._save_source(conn, s)
        return len(sources)

    def _save_source(self, conn, s: NewsSource) -> None:
        conn.execute(
            """INSERT INTO news_sources(source_id,name,category,reliability_class,
               country,language,domain,enabled,last_ingested,data,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(source_id) DO UPDATE SET name=excluded.name,
                 category=excluded.category,
                 reliability_class=excluded.reliability_class,
                 country=excluded.country, language=excluded.language,
                 domain=excluded.domain, enabled=excluded.enabled,
                 last_ingested=excluded.last_ingested, data=excluded.data,
                 updated_at=excluded.updated_at""",
            (s.source_id, s.name, s.category.value, s.reliability_class.value,
             s.country, s.language, s.domain, 1 if s.enabled else 0,
             s.last_ingested, json.dumps(s.to_dict()), time.time()))

    def get_source(self, source_id: str) -> Optional[NewsSource]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT data FROM news_sources WHERE source_id=?",
                (source_id,)).fetchone()
            return NewsSource.from_dict(json.loads(row["data"])) if row else None

    def list_sources(self, *, enabled_only: bool = False) -> List[NewsSource]:
        q = "SELECT data FROM news_sources"
        if enabled_only:
            q += " WHERE enabled=1"
        with self._conn() as conn:
            return [NewsSource.from_dict(json.loads(r["data"]))
                    for r in conn.execute(q).fetchall()]

    # ------------------------------------------------------------------ #
    # feeds
    # ------------------------------------------------------------------ #
    def save_feed(self, feed: Feed) -> None:
        with self._conn() as conn:
            self._save_feed(conn, feed)

    def save_feeds(self, feeds: List[Feed]) -> int:
        with self._conn() as conn:
            for f in feeds:
                self._save_feed(conn, f)
        return len(feeds)

    def _save_feed(self, conn, f: Feed) -> None:
        conn.execute(
            """INSERT INTO news_feeds(feed_id,url,source_id,provider,enabled,
               last_polled,data,updated_at) VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(feed_id) DO UPDATE SET url=excluded.url,
                 source_id=excluded.source_id, provider=excluded.provider,
                 enabled=excluded.enabled, last_polled=excluded.last_polled,
                 data=excluded.data, updated_at=excluded.updated_at""",
            (f.feed_id, f.url, f.source_id, f.provider, 1 if f.enabled else 0,
             f.last_polled, json.dumps(f.to_dict()), time.time()))

    def get_feed(self, feed_id: str) -> Optional[Feed]:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM news_feeds WHERE feed_id=?",
                               (feed_id,)).fetchone()
            return Feed.from_dict(json.loads(row["data"])) if row else None

    def list_feeds(self, *, enabled_only: bool = False) -> List[Feed]:
        q = "SELECT data FROM news_feeds"
        if enabled_only:
            q += " WHERE enabled=1"
        with self._conn() as conn:
            return [Feed.from_dict(json.loads(r["data"]))
                    for r in conn.execute(q).fetchall()]

    # ------------------------------------------------------------------ #
    # articles
    # ------------------------------------------------------------------ #
    def article_exists(self, *, content_hash: str = "",
                       canonical_url: str = "", article_id: str = "") -> bool:
        clauses, params = [], []
        if article_id:
            clauses.append("article_id=?")
            params.append(article_id)
        if content_hash:
            clauses.append("content_hash=?")
            params.append(content_hash)
        if canonical_url:
            clauses.append("canonical_url=?")
            params.append(canonical_url)
        if not clauses:
            return False
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM news_articles WHERE " + " OR ".join(clauses)
                + " LIMIT 1", params).fetchone()
            return row is not None

    def save_article(self, article: Article) -> None:
        with self._conn() as conn:
            self._save_article(conn, article)

    def save_articles(self, articles: List[Article]) -> int:
        with self._conn() as conn:
            for a in articles:
                self._save_article(conn, a)
        return len(articles)

    def _save_article(self, conn, a: Article) -> None:
        conn.execute(
            """INSERT INTO news_articles(article_id,title,url,canonical_url,
               source_id,source_name,source_domain,language,publication_date,
               ingestion_date,content_hash,simhash,duplicate_of,data,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(article_id) DO UPDATE SET title=excluded.title,
                 url=excluded.url, canonical_url=excluded.canonical_url,
                 source_id=excluded.source_id, source_name=excluded.source_name,
                 source_domain=excluded.source_domain, language=excluded.language,
                 publication_date=excluded.publication_date,
                 content_hash=excluded.content_hash, simhash=excluded.simhash,
                 duplicate_of=excluded.duplicate_of, data=excluded.data,
                 updated_at=excluded.updated_at""",
            (a.article_id, a.title, a.url, a.canonical_url, a.source_id,
             a.source_name, a.source_domain, a.language, a.publication_date,
             a.ingestion_date, a.content_hash, str(a.simhash), a.duplicate_of,
             json.dumps(a.to_dict()), time.time()))
        # normalized entity + ioc rows
        conn.execute("DELETE FROM news_entities WHERE article_id=?",
                     (a.article_id,))
        conn.execute("DELETE FROM news_iocs WHERE article_id=?", (a.article_id,))
        for m in a.entity_mentions:
            conn.execute(
                """INSERT OR REPLACE INTO news_entities(entity_key,article_id,
                   entity_type,value,surface,extractor,weight,data)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (m.entity_key, a.article_id, m.entity_type.value, m.value,
                 m.surface, m.extractor, m.weight, json.dumps(m.to_dict())))
            if m.is_ioc:
                conn.execute(
                    """INSERT OR REPLACE INTO news_iocs(ioc_key,article_id,
                       ioc_type,value,first_seen,last_seen)
                       VALUES (?,?,?,?,?,?)""",
                    (m.entity_key, a.article_id, m.entity_type.value, m.value,
                     a.publication_date, a.publication_date))
        # evidence rows
        for ev in a.evidence:
            rid = ev.get("ref_id") or ev.get("content_hash", "")
            if not rid:
                continue
            conn.execute(
                """INSERT OR REPLACE INTO news_evidence(ref_id,owner_key,provider,
                   source_url,observed_at,data) VALUES (?,?,?,?,?,?)""",
                (rid, a.article_id, ev.get("provider", ""),
                 ev.get("source_url", ""), float(ev.get("observed_at", 0) or 0),
                 json.dumps(ev)))

    def get_article(self, article_id: str) -> Optional[Article]:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM news_articles WHERE article_id=?",
                               (article_id,)).fetchone()
            return Article.from_dict(json.loads(row["data"])) if row else None

    def iter_articles(self, *, since: float = 0.0, until: float = 0.0,
                      source_domain: str = "", limit: int = 0,
                      include_duplicates: bool = False
                      ) -> Iterator[Article]:
        q = "SELECT data FROM news_articles WHERE 1=1"
        params: List[Any] = []
        if since:
            q += " AND publication_date >= ?"
            params.append(since)
        if until:
            q += " AND publication_date <= ?"
            params.append(until)
        if source_domain:
            q += " AND source_domain = ?"
            params.append(source_domain)
        if not include_duplicates:
            q += " AND (duplicate_of = '' OR duplicate_of IS NULL)"
        q += " ORDER BY publication_date DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._conn() as conn:
            for r in conn.execute(q, params):
                yield Article.from_dict(json.loads(r["data"]))

    def list_articles(self, **kw) -> List[Article]:
        return list(self.iter_articles(**kw))

    def count_articles(self) -> int:
        with self._conn() as conn:
            return int(conn.execute(
                "SELECT COUNT(*) AS c FROM news_articles").fetchone()["c"])

    # ------------------------------------------------------------------ #
    # entity queries
    # ------------------------------------------------------------------ #
    def articles_for_entity(self, *, value: str = "", entity_key: str = "",
                            entity_type: str = "", since: float = 0.0
                            ) -> List[str]:
        q = ("SELECT DISTINCT e.article_id FROM news_entities e "
             "JOIN news_articles a ON a.article_id = e.article_id WHERE 1=1")
        params: List[Any] = []
        if entity_key:
            q += " AND e.entity_key = ?"
            params.append(entity_key)
        if value:
            q += " AND lower(e.value) = ?"
            params.append(value.lower())
        if entity_type:
            q += " AND e.entity_type = ?"
            params.append(entity_type)
        if since:
            q += " AND a.publication_date >= ?"
            params.append(since)
        with self._conn() as conn:
            return [r["article_id"] for r in conn.execute(q, params).fetchall()]

    def entity_counts(self, entity_type: str, *, since: float = 0.0,
                      limit: int = 25) -> List[Dict[str, Any]]:
        q = ("SELECT e.value AS value, COUNT(DISTINCT e.article_id) AS n "
             "FROM news_entities e JOIN news_articles a "
             "ON a.article_id = e.article_id WHERE e.entity_type = ?")
        params: List[Any] = [entity_type]
        if since:
            q += " AND a.publication_date >= ?"
            params.append(since)
        q += " GROUP BY lower(e.value) ORDER BY n DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as conn:
            return [{"value": r["value"], "count": r["n"]}
                    for r in conn.execute(q, params).fetchall()]

    def ioc_cross_source(self, *, min_domains: int = 2, since: float = 0.0
                         ) -> List[Dict[str, Any]]:
        """IOC values that appear across >= min_domains distinct source domains."""
        q = ("SELECT i.value AS value, i.ioc_type AS ioc_type, "
             "COUNT(DISTINCT a.source_domain) AS domains, "
             "COUNT(DISTINCT i.article_id) AS articles "
             "FROM news_iocs i JOIN news_articles a "
             "ON a.article_id = i.article_id WHERE 1=1")
        params: List[Any] = []
        if since:
            q += " AND a.publication_date >= ?"
            params.append(since)
        q += (" GROUP BY lower(i.value) HAVING domains >= ? "
              "ORDER BY domains DESC, articles DESC")
        params.append(int(min_domains))
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(q, params).fetchall()]

    # ------------------------------------------------------------------ #
    # clusters / topics / campaigns / timeline / reports (generic blob rows)
    # ------------------------------------------------------------------ #
    def save_cluster(self, cluster: Cluster) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO news_clusters(cluster_id,kind,label,size,first_seen,
                   last_seen,data,updated_at) VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(cluster_id) DO UPDATE SET kind=excluded.kind,
                     label=excluded.label, size=excluded.size,
                     first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (cluster.cluster_id, cluster.kind.value, cluster.label,
                 cluster.size, cluster.first_seen, cluster.last_seen,
                 json.dumps(cluster.to_dict()), time.time()))

    def list_clusters(self, *, kind: str = "") -> List[Cluster]:
        q = "SELECT data FROM news_clusters"
        params: List[Any] = []
        if kind:
            q += " WHERE kind=?"
            params.append(kind)
        q += " ORDER BY last_seen DESC"
        with self._conn() as conn:
            return [Cluster.from_dict(json.loads(r["data"]))
                    for r in conn.execute(q, params).fetchall()]

    def save_topic(self, topic: Topic) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO news_topics(topic_id,label,first_seen,last_seen,
                   data,updated_at) VALUES (?,?,?,?,?,?)
                   ON CONFLICT(topic_id) DO UPDATE SET label=excluded.label,
                     first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (topic.topic_id, topic.label, topic.first_seen, topic.last_seen,
                 json.dumps(topic.to_dict()), time.time()))

    def list_topics(self) -> List[Topic]:
        with self._conn() as conn:
            return [Topic.from_dict(json.loads(r["data"]))
                    for r in conn.execute(
                        "SELECT data FROM news_topics ORDER BY last_seen DESC")]

    def save_campaign(self, campaign: Any) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO news_campaigns(campaign_key,name,first_reported,
                   last_reported,mention_count,data,updated_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(campaign_key) DO UPDATE SET name=excluded.name,
                     first_reported=excluded.first_reported,
                     last_reported=excluded.last_reported,
                     mention_count=excluded.mention_count, data=excluded.data,
                     updated_at=excluded.updated_at""",
                (campaign.key, campaign.name, campaign.first_reported,
                 campaign.last_reported, campaign.mention_count,
                 json.dumps(campaign.to_dict()), time.time()))

    def get_campaign(self, campaign_key: str):
        from ..models.campaign import CampaignNews
        with self._conn() as conn:
            row = conn.execute(
                "SELECT data FROM news_campaigns WHERE campaign_key=?",
                (campaign_key,)).fetchone()
            return CampaignNews.from_dict(json.loads(row["data"])) if row else None

    def list_campaigns(self) -> List[Any]:
        from ..models.campaign import CampaignNews
        with self._conn() as conn:
            return [CampaignNews.from_dict(json.loads(r["data"]))
                    for r in conn.execute(
                        "SELECT data FROM news_campaigns "
                        "ORDER BY last_reported DESC")]

    def add_timeline_event(self, *, event_id: str, subject_key: str,
                           subject_type: str, ts: float, article_id: str,
                           label: str, detail: Optional[Dict[str, Any]] = None
                           ) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO news_timeline(event_id,subject_key,
                   subject_type,ts,article_id,label,data) VALUES (?,?,?,?,?,?,?)""",
                (event_id, subject_key, subject_type, ts, article_id, label,
                 json.dumps(detail or {})))

    def timeline_for(self, subject_key: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT event_id,ts,article_id,label,subject_type,data "
                "FROM news_timeline WHERE subject_key=? ORDER BY ts ASC",
                (subject_key,)).fetchall()
            out = []
            for r in rows:
                d = {"event_id": r["event_id"], "ts": r["ts"],
                     "article_id": r["article_id"], "label": r["label"],
                     "subject_type": r["subject_type"]}
                d.update(json.loads(r["data"] or "{}"))
                out.append(d)
            return out

    def save_report(self, report: NewsReport) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO news_reports(report_id,report_type,subject,
                   generated_at,data,updated_at) VALUES (?,?,?,?,?,?)
                   ON CONFLICT(report_id) DO UPDATE SET report_type=excluded.report_type,
                     subject=excluded.subject, generated_at=excluded.generated_at,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (report.report_id, report.report_type, report.subject,
                 report.generated_at, json.dumps(report.to_dict()), time.time()))

    def get_report(self, report_id: str) -> Optional[NewsReport]:
        with self._conn() as conn:
            row = conn.execute("SELECT data FROM news_reports WHERE report_id=?",
                               (report_id,)).fetchone()
            return NewsReport.from_dict(json.loads(row["data"])) if row else None

    def list_reports(self, *, report_type: str = "") -> List[Dict[str, Any]]:
        q = "SELECT report_id,report_type,subject,generated_at FROM news_reports"
        params: List[Any] = []
        if report_type:
            q += " WHERE report_type=?"
            params.append(report_type)
        q += " ORDER BY generated_at DESC"
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(q, params).fetchall()]

    # ------------------------------------------------------------------ #
    # relationships
    # ------------------------------------------------------------------ #
    def save_relationship(self, *, rel_id: str, src_type: str, src_key: str,
                          dst_type: str, dst_key: str, rel_type: str,
                          weight: float, detail: Optional[Dict[str, Any]] = None
                          ) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO news_relationships(rel_id,src_type,src_key,dst_type,
                   dst_key,rel_type,weight,data,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(rel_id) DO UPDATE SET weight=excluded.weight,
                     data=excluded.data, updated_at=excluded.updated_at""",
                (rel_id, src_type, src_key, dst_type, dst_key, rel_type,
                 weight, json.dumps(detail or {}), time.time()))

    def relationships_for(self, key: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM news_relationships WHERE src_key=? OR dst_key=?",
                (key, key)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["detail"] = json.loads(d.pop("data", "{}") or "{}")
                out.append(d)
            return out

    # ------------------------------------------------------------------ #
    # provider state (incremental ingestion) + kv
    # ------------------------------------------------------------------ #
    def get_provider_state(self, provider: str, resource: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT etag,last_modified,last_run,cursor FROM provider_state "
                "WHERE provider=? AND resource=?", (provider, resource)).fetchone()
            return dict(row) if row else {"etag": "", "last_modified": "",
                                          "last_run": 0.0, "cursor": ""}

    def set_provider_state(self, provider: str, resource: str, *, etag: str = "",
                           last_modified: str = "", cursor: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO provider_state(provider,resource,etag,last_modified,
                   last_run,cursor) VALUES (?,?,?,?,?,?)
                   ON CONFLICT(provider,resource) DO UPDATE SET etag=excluded.etag,
                     last_modified=excluded.last_modified, last_run=excluded.last_run,
                     cursor=excluded.cursor""",
                (provider, resource, etag, last_modified, time.time(), cursor))

    def kv_get(self, namespace: str, key: str, default: Any = None) -> Any:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM kv WHERE namespace=? AND key=?",
                (namespace, key)).fetchone()
            return json.loads(row["value"]) if row else default

    def kv_set(self, namespace: str, key: str, value: Any) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO kv(namespace,key,value,updated_at) VALUES (?,?,?,?)
                   ON CONFLICT(namespace,key) DO UPDATE SET value=excluded.value,
                     updated_at=excluded.updated_at""",
                (namespace, key, json.dumps(value), time.time()))

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._conn() as conn:
            def c(t):
                return int(conn.execute(f"SELECT COUNT(*) AS c FROM {t}").fetchone()["c"])
            return {
                "articles": c("news_articles"), "sources": c("news_sources"),
                "feeds": c("news_feeds"), "entities": c("news_entities"),
                "iocs": c("news_iocs"), "campaigns": c("news_campaigns"),
                "relationships": c("news_relationships"),
                "topics": c("news_topics"), "clusters": c("news_clusters"),
                "timeline": c("news_timeline"), "reports": c("news_reports"),
                "evidence": c("news_evidence"),
                "schema_version": self.schema_version(),
            }


__all__ = ["SQLiteStore", "DEFAULT_DB_PATH", "SCHEMA_VERSION"]
