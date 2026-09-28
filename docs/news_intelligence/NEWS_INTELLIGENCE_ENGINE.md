# News Intelligence Engine v2.0

The **News Intelligence Engine** (`news_intelligence/`) is Sombra Guardian's
production-grade Cyber OSINT / news-intelligence subsystem. It continuously
collects, normalizes, deduplicates, enriches, correlates, scores, stores and
visualizes **publicly available** news and intelligence reporting about
cybersecurity — threat actors, malware, infrastructure, vulnerabilities,
campaigns, organizations, governments, technology vendors, public incidents and
geopolitical cyber events.

It is a sibling of the Threat Actor Intelligence Engine and reuses its evidence,
confidence and indicator-parsing primitives so the two speak one evidence
language.

## Core principle

Works entirely from public sources. It **never fabricates** a news item, a
source, or an attribution. Every stored fact anchors to an `EvidenceRef` back to
the article it came from; every correlation is an explainable relationship with a
computed `ConfidenceModel` (evidence quality, **not** certainty of a claim); and
every report renders the standing limitations:

- a news story is a **publisher's claim**, not a verified fact;
- multiple copies of one wire/syndicated story are **not** independent
  corroboration — corroboration is counted across distinct originating outlets
  only;
- any attribution, victim naming or severity wording is the **publisher's**; the
  engine asserts nothing beyond what the cited article states.

## Security boundary

Intelligence **collection and analysis only**. The engine implements no
credential harvesting, no login/paywall bypass, no malware download, no exploit
automation, and no phishing or social-engineering automation. IOCs are stored as
**references** to public reporting, never as sample bytes, and nothing is ever
fetched from an indicator.

## Primary questions answered

| Question | API |
|---|---|
| Which threat actors appeared today? | `engine.actors_today()` / `top_entities('threat_actor')` |
| Which campaigns are discussed across multiple vendors? | `engine.vendor_comparison()`, `engine.campaigns()` |
| Which CVEs are receiving increased attention? | `engine.trends('cve')` |
| Which malware families appeared this week? | `engine.malware_this_week()` |
| Which countries/industries recur? | `engine.top_entities('country')` |
| Which organizations have multiple independent reports? | `engine.corroboration(name)` |
| Which infrastructure indicators appear across unrelated sources? | `engine.cross_source_infrastructure()` |
| Which events are new vs historical? | `engine.events()`, timeline `new_vs_historical` |
| Which reports corroborate each other? | `engine.related_articles()`, `corroboration()` |
| What changed since yesterday? | `engine.whats_new()` |

## Architecture

```
news_intelligence/
  models/       typed domain + epistemics (evidence/confidence reused from CTI)
  storage/      SQLite persistence (normalized tables, incremental state) + cache
  ingestion/    passive public collectors (RSS/Atom/JSON, vendor, CISA/KEV, CERT,
                NVD, GitHub advisories, exploit blogs, podcasts)
  parsing/      HTML → normalized fields (readability, OpenGraph, schema.org, dates)
  extraction/   pure entity extraction reusing the CTI indicator miner
  clustering/   duplicate / event / topic / campaign clustering (SimHash/MinHash/TFIDF)
  correlation/  explainable, evidence-gated correlation + source corroboration
  timeline/     evidence-dated chronologies
  trend.py      trend detection (with sample size + observation window)
  providers/    source-category → ingestor binding + registry
  graph/        provenance-carrying relationship graphs (JSON/GraphML/GEXF/DOT)
  reports/      daily/weekly briefs + actor/malware/CVE/campaign/executive profiles
  search.py     internal search + advanced filtering
  language.py   language detection + optional metadata translation
  integration.py bridges to the other Sombra Guardian engines
  telegram/     the /news* command surface
  pipeline.py   resolve ingest results into stored, deduped, enriched articles
  orchestrator.py ingestion + correlation conductor
  scheduler.py  recurring, incremental, backoff-aware ingestion
  engine.py     the public query API
```

## Data flow

```
sources → providers → ingestors (fetch+parse) → IngestResult(Article[])
   → pipeline (dedup + entity extraction + evidence + confidence + persist + timeline)
   → correlation + clustering (events, campaigns, relationships)
   → engine queries / reports / graph / telegram
   → integration hub → Threat Actor Intel / Web Footprint / Geo-OSINT / Entity Fusion / Behavioral
```

Every stage is **idempotent** and **incremental**: re-ingesting a feed changes
nothing, and only changed resources are re-fetched (ETag / Last-Modified
validators are stored per feed).

## Configuration

All settings resolve from the environment at runtime (never at import). Highlights
(see `configuration.py` for the full list):

| Env var | Default | Meaning |
|---|---|---|
| `NI_DB_PATH` | `news_intelligence.db` | SQLite path |
| `NI_CACHE_DIR` | `.ni_cache` | disk cache dir |
| `NI_POLL_INTERVAL` | `3600` | default feed poll interval (s) |
| `NI_SIMHASH_HAMMING` | `3` | near-duplicate SimHash threshold |
| `NI_MINHASH_JACCARD` | `0.7` | near-duplicate MinHash threshold |
| `NI_EVENT_WINDOW_HOURS` | `72` | max span for event clustering |
| `NI_TREND_WINDOW_DAYS` | `7` | trend comparison window |
| `NI_EXTRA_FEEDS` | — | comma-separated extra feed URLs |
| `NVD_API_KEY`, `GITHUB_TOKEN` | — | raise provider rate limits (optional) |

A provider without its key is simply skipped, so the engine runs from "local RSS
only" up to "every configured public source" with zero code change.

## Quick start

```python
from news_intelligence import NewsIntelligenceEngine
eng = NewsIntelligenceEngine()
eng.bootstrap_sources()              # seed the default public source registry

# offline: feed already-parsed Article objects
from news_intelligence.ingestion import RSSIngestor
res = RSSIngestor().parse(rss_bytes, source=my_source)
eng.ingest_articles(res.articles)

print(eng.daily_brief(fmt="markdown"))
print(eng.actor_report("APT29", fmt="markdown"))
print(eng.cross_source_infrastructure(days=7))
```

## Telegram

`/news`, `/news_today`, `/news_week`, `/news_search`, `/news_actor`,
`/news_campaign`, `/news_cve`, `/news_malware`, `/news_org`, `/news_country`,
`/news_graph`, `/news_brief`, `/news_report`. All read-only. See
`TELEGRAM_COMMANDS` in the source docstrings.

## Database

Normalized tables: `news_articles`, `news_sources`, `news_feeds`,
`news_entities`, `news_iocs`, `news_campaigns`, `news_relationships`,
`news_topics`, `news_clusters`, `news_timeline`, `news_reports`, `news_evidence`,
plus `provider_state` (incremental) and `kv`. Each object is stored as a lossless
JSON blob plus indexed scalar columns.
