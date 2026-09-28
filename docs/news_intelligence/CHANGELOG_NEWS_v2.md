# Changelog — News Intelligence Engine

## v2.0.0 — News Intelligence Engine (major)

Introduces `news_intelligence/`, a production-grade Cyber OSINT / news-intelligence
subsystem for Sombra Guardian. Async-friendly, SQLite-backed, evidence-driven, and
built from public sources only.

### Added

**Domain model** (`models/`)
- `Article` — the normalized news atom, preserving every spec CORE-DATA-MODEL field
  and self-citing via `as_evidence()`; typed entity buckets rebuilt from mentions.
- `NewsSource` / `Feed` — source registry + incremental feed state (ETag/Last-Modified,
  poll interval, failure backoff).
- `EntityMention` — typed, normalized, provenance-preserving extracted entity.
- `ActorNews` / `MalwareNews` / `CVENews` / `CampaignNews` — profile aggregates that
  preserve vendor aliases separately and record differing claims.
- `Topic` / `Cluster` / `NewsEvent`, `NewsReport` / `ReportSection`.
- Evidence + confidence primitives **re-used** from `threat_actor_intelligence` so
  all engines speak one evidence language; adds news-specific standing limitations.

**Ingestion** (`ingestion/`) — RSS, Atom, JSON Feed, vendor blogs (with optional
full-page enrichment), CISA advisories + KEV catalog, CERT feeds, NVD CVE API,
GitHub security advisories (atom + REST), exploit-research blogs, podcasts. Polite
conditional HTTP with rate limiting; pure parsers unit-tested offline.

**Parsing** (`parsing/`) — HTML→text, readability main-content, OpenGraph/meta,
schema.org JSON-LD, author bylines, publication dates.

**Extraction** (`extraction/`) — IOC/URL/CVE/CWE/CAPEC/ATT&CK/actor/malware/org/geo
extractors composed by `EntityExtractor`, reusing the CTI indicator miner; curated
public alias clusters preserve vendor aliases without merging identities.

**Clustering** (`clustering/`) — SimHash/MinHash/TF-IDF similarity; duplicate,
event, topic and campaign clustering with explainable signals.

**Correlation** (`correlation/`) — entity, article, infrastructure (cross-source
IOC), source-corroboration, campaign and topic/vendor-comparison correlators, all
evidence-gated with computed confidence; contradictions recorded, never resolved.

**Timeline** (`timeline/`) — evidence-dated corpus/actor/campaign/CVE/malware
chronologies with new-vs-historical splitting.

**Trend** (`trend.py`) — rising/falling/emerging detection with mandatory sample
size + observation window.

**Providers** (`providers/`) — source-category → ingestor registry with graceful
degradation when a provider key is absent.

**Graph** (`graph/`) — provenance-carrying news/actor/campaign/topic graphs with
JSON/GraphML/GEXF/DOT export (stdlib only).

**Reports** (`reports/`) — Daily Intelligence Brief, Weekly Threat Brief,
Actor/Malware/CVE/Campaign profiles, Executive Summary; Markdown/HTML/JSON/CSV
renderers. Every report carries the standing limitations.

**Storage** (`storage/`) — SQLite store with normalized tables
(`news_articles`, `news_sources`, `news_feeds`, `news_entities`, `news_iocs`,
`news_campaigns`, `news_relationships`, `news_topics`, `news_clusters`,
`news_timeline`, `news_reports`, `news_evidence`, `provider_state`, `kv`), WAL,
versioned migrations, incremental state; disk cache reusing the CTI cache.

**Search / language / integration** — internal search + advanced filters;
dependency-free language detection with opt-in metadata translation; best-effort
bridges to Threat Actor Intelligence, Web Footprint, Geo-OSINT, Entity Fusion and
Behavioral Intelligence (references only).

**Orchestration** — `Pipeline` (dedup + extract + evidence + persist + timeline),
`Orchestrator` (collect → pipeline → correlate → integrate) and `Scheduler`
(recurring, incremental, backoff-aware).

**Engine + Telegram** — `NewsIntelligenceEngine` public API and the `/news*`
command surface (`/news /news_today /news_week /news_search /news_actor
/news_campaign /news_cve /news_malware /news_org /news_country /news_graph
/news_brief /news_report`), registered in `app.py` collision-safe and guarded.

**Tests** — 86 offline tests across models, RSS/ingestion, parsing, extraction,
clustering, pipeline, storage, correlation, trend/search, reports, timeline/graph,
scheduler/orchestrator, engine and telegram.

**Docs** — `NEWS_INTELLIGENCE_ENGINE.md`, `RSS_PROVIDER_GUIDE.md`,
`ENTITY_EXTRACTION.md`, `CORRELATION_ENGINE.md`, `NEWS_GRAPH_ENGINE.md`, this
changelog.

### Security boundary

Intelligence collection/analysis only: no credential harvesting, no login/paywall
bypass, no malware download, no exploit automation, no phishing/social-engineering
automation. IOCs stored as references to public reporting.
