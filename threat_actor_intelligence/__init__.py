"""
threat_actor_intelligence/ — the Threat Actor Intelligence Engine for Sombra Guardian.

WHAT THIS IS
------------
A production-grade Cyber Threat Intelligence (CTI) subsystem that collects,
normalizes, correlates, scores, stores and visualizes *publicly available*
intelligence about threat actors, malware families, campaigns, indicators of
compromise, infrastructure, aliases, ATT&CK/CAPEC TTPs, reports and historical
activity.

It answers, with traceable evidence on every conclusion:
  * which public reports mention this actor;
  * which aliases are reported for the same actor (never merged blindly);
  * which malware families / campaigns / infrastructure are associated;
  * which public IOCs belong to campaigns and which infrastructure overlaps;
  * which ATT&CK techniques and CAPEC patterns are documented;
  * which countries/industries are targeted per public reporting;
  * the evidence-dated timeline of activity;
  * which independent sources corroborate the same campaign.

CORE PRINCIPLE (enforced in code, not just documented)
------------------------------------------------------
Uses PUBLIC information only. Never fabricates attribution. Never infers criminal
responsibility beyond documented public sources. Every stored fact anchors to an
``EvidenceRef``; every correlation is an explainable ``Relationship`` with a
computed ``ConfidenceModel`` (evidence quality, not certainty of guilt); every
report renders the standing limitations (aliases ≠ identity; absence of a source
≠ absence of activity; no attribution beyond cited sources).

SECURITY BOUNDARY
-----------------
This is an intelligence *analysis* system. It implements no malware execution,
payload/exploit/phishing generation, credential theft, persistence, C2, scanning
or exploit automation. Malware families are catalog metadata only — hashes are
*references to* public samples, never sample bytes.

ARCHITECTURE
------------
  models/        typed CTI domain + epistemics (evidence, confidence, entities)
  storage/       SQLite persistence (normalized tables, incremental state) + cache
  ingestion/     passive public-source collectors (RSS, STIX, TAXII, CISA, NVD,
                 OTX, URLhaus, MalwareBazaar, GitHub, vendor) — pure parse + I/O
  mitre/         ATT&CK + CAPEC knowledge bases and mappers
  correlation/   explainable, evidence-gated correlation + careful alias handling
  timeline/      evidence-dated chronologies
  graph/         relationship graphs (GraphML/GEXF/JSON/DOT)
  reports/       actor/campaign/malware dossiers + markdown/html/json/csv
  telegram/      the /actor /campaign /malware /ioc /attack ... command surface
  pipeline.py    resolve ingest results into stored entities (idempotent)
  orchestrator.py ingestion + correlation conductor
  engine.py      the public query API
  scheduler.py   incremental scheduled ingestion

All provider API keys come from the environment; a provider without its key is
skipped, so the engine runs from "MITRE + local feeds only" up to "every
configured public source" with zero code change.
"""

from .configuration import TAIConfig, get_config, ProviderConfig
from .engine import ThreatActorIntelligenceEngine
from .orchestrator import Orchestrator, OrchestrationResult
from .pipeline import ResolutionPipeline, PipelineStats
from .scheduler import IngestionScheduler
from .storage.sqlite_store import SQLiteStore

__version__ = "1.0.0"

__all__ = [
    "TAIConfig", "get_config", "ProviderConfig",
    "ThreatActorIntelligenceEngine", "Orchestrator", "OrchestrationResult",
    "ResolutionPipeline", "PipelineStats", "IngestionScheduler", "SQLiteStore",
    "__version__",
]
