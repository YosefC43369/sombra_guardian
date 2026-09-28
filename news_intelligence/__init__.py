"""
news_intelligence/ — the News Intelligence Engine v2.0 for Sombra Guardian.

WHAT THIS IS
------------
A production-grade Cyber OSINT / News Intelligence subsystem that continuously
collects, normalizes, deduplicates, enriches, correlates, scores, stores and
visualizes *publicly available* news and intelligence reports about cybersecurity:
threat actors, malware, infrastructure, vulnerabilities, campaigns, organizations,
governments, technology vendors, public incidents and geopolitical cyber events.

It answers, with traceable evidence on every conclusion:
  * which threat actors / malware / CVEs / campaigns appeared, and when;
  * which are discussed across multiple independent vendors;
  * which infrastructure indicators recur across unrelated sources;
  * which reports corroborate each other, and which contradict;
  * which events are new versus historical, and what changed since yesterday.

CORE PRINCIPLE (enforced in code, not just documented)
------------------------------------------------------
Works entirely from public sources. Never fabricates a news item, a source, or an
attribution. Every stored fact anchors to an ``EvidenceRef`` back to the article it
came from; every correlation is an explainable relationship with a computed
``ConfidenceModel`` (evidence quality, not certainty of a claim); every report renders
the standing limitations (a story is a publisher's claim, syndicated copies are not
independent corroboration, attribution is the publisher's).

SECURITY BOUNDARY
-----------------
Intelligence *collection and analysis* only. It implements no credential harvesting,
no login/paywall bypass, no malware download, no exploit automation, no phishing or
social-engineering automation. IOCs are stored as references to public reporting.

ARCHITECTURE
------------
  models/       typed domain + epistemics (evidence, confidence re-used from CTI)
  storage/      SQLite persistence (normalized tables, incremental state) + cache
  ingestion/    passive public collectors (RSS/Atom/JSON, vendor, CISA/KEV, CERT,
                NVD, GitHub advisories, exploit blogs, podcasts) — pure parse + I/O
  parsing/      HTML → normalized fields (readability, OpenGraph, schema.org, dates)
  extraction/   pure entity extraction (IOC/CVE/actor/malware/org/geo/ATT&CK) reusing
                the CTI indicator miner
  clustering/   duplicate / event / topic / campaign clustering (SimHash/MinHash/TFIDF)
  correlation/  explainable, evidence-gated correlation + source corroboration
  timeline/     evidence-dated chronologies
  trend.py      trend detection (with sample size + observation window)
  providers/    source-category → ingestor binding + registry
  graph/        provenance-carrying relationship graphs (JSON/GraphML/GEXF/DOT)
  reports/      daily/weekly briefs + actor/malware/CVE/campaign/executive profiles
                and markdown/html/json/csv renderers
  search.py     internal search + advanced filtering
  language.py   language detection + optional metadata translation
  integration.py bridges to Threat Actor Intel / Entity Fusion / Web Footprint /
                Geo-OSINT / Behavioral Intelligence
  telegram/     the /news* command surface
  pipeline.py   resolve ingest results into stored, deduped, enriched articles
  orchestrator.py ingestion + correlation conductor
  scheduler.py  recurring, incremental, backoff-aware ingestion
  engine.py     the public query API

All provider API keys come from the environment; a provider without its key is skipped,
so the engine runs from "local RSS only" up to "every configured public source" with
zero code change.
"""

from .configuration import (NewsIntelConfig, ProviderConfig, get_config,
                            default_sources)
from .engine import NewsIntelligenceEngine
from .pipeline import Pipeline, PipelineResult
from .orchestrator import Orchestrator, OrchestrationResult
from .scheduler import Scheduler, SchedulerTick
from .trend import TrendEngine, Trend
from .search import SearchEngine, FilterEngine, SearchQuery
from .language import LanguageEngine, detect_language
from .integration import IntegrationHub

__version__ = "2.0.0"

__all__ = [
    "NewsIntelConfig", "ProviderConfig", "get_config", "default_sources",
    "NewsIntelligenceEngine", "Pipeline", "PipelineResult",
    "Orchestrator", "OrchestrationResult", "Scheduler", "SchedulerTick",
    "TrendEngine", "Trend", "SearchEngine", "FilterEngine", "SearchQuery",
    "LanguageEngine", "detect_language", "IntegrationHub", "__version__",
]
