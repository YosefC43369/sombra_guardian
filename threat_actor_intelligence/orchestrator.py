"""
threat_actor_intelligence.orchestrator — the ingestion + correlation conductor.

Ties the layers together:
  1. instantiate the configured, *available* ingestors (a provider missing its
     API key is skipped, not an error);
  2. run each (fetch → parse → ``IngestResult``);
  3. resolve results through the ``ResolutionPipeline`` into stored entities;
  4. run the correlation engines across the freshly-updated store and persist the
     evidence-graded relationships.

It exposes both a full ``run_all`` and per-provider / offline (``ingest_result``)
entry points so tests drive the whole flow without touching the network.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .configuration import TAIConfig, get_config
from .storage.sqlite_store import SQLiteStore
from .storage.cache_store import CacheStore
from .ingestion import INGESTORS
from .ingestion.base import IngestResult, HTTPClient
from .pipeline import ResolutionPipeline, PipelineStats
from .mitre.attack_engine import ATTACKEngine
from .mitre.capec_engine import CAPECEngine
from .correlation.actor_correlation import ActorCorrelator
from .correlation.campaign_correlation import CampaignCorrelator
from .correlation.malware_correlation import MalwareCorrelator
from .correlation.infrastructure_correlation import InfrastructureCorrelator
from .correlation.ioc_correlation import IOCCorrelator
from .correlation.report_correlation import ReportCorrelator


@dataclass
class OrchestrationResult:
    pipeline: Dict[str, int] = field(default_factory=dict)
    correlation: Dict[str, int] = field(default_factory=dict)
    providers_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"pipeline": self.pipeline, "correlation": self.correlation,
                "providers_run": self.providers_run, "errors": self.errors,
                "duration_seconds": round(self.duration_seconds, 3)}


class Orchestrator:
    def __init__(self, *, config: Optional[TAIConfig] = None,
                 store: Optional[SQLiteStore] = None,
                 attack: Optional[ATTACKEngine] = None,
                 capec: Optional[CAPECEngine] = None,
                 cache: Optional[CacheStore] = None):
        self.config = config or get_config()
        self.store = store or SQLiteStore(self.config.db_path)
        self.attack = attack or ATTACKEngine().load_seed()
        self.capec = capec or CAPECEngine().load_seed()
        self.cache = cache or CacheStore(store=self.store,
                                         cache_dir=self.config.cache_dir,
                                         default_ttl=self.config.cache_ttl_seconds)
        self.pipeline = ResolutionPipeline(self.store, attack=self.attack)

    # -- ingestor construction -------------------------------------------- #

    def build_ingestor(self, provider: str):
        cls = INGESTORS.get(provider)
        if cls is None:
            return None
        pcfg = self.config.provider(provider)
        http = HTTPClient(user_agent=self.config.user_agent,
                          timeout=self.config.http_timeout_seconds,
                          rate_limit_per_min=pcfg.rate_limit_per_min)
        return cls(http=http, api_key=pcfg.api_key() or "")

    # -- offline / test-friendly entry ------------------------------------ #

    def ingest_result(self, result: IngestResult) -> PipelineStats:
        """Resolve an already-parsed IngestResult into the store (no network)."""
        return self.pipeline.process(result)

    def correlate(self, *, now: Optional[float] = None) -> Dict[str, int]:
        """Run all correlators across the current store; persist relationships."""
        now = now if now is not None else time.time()
        counts: Dict[str, int] = {}

        actors = self.store.list_actors(limit=5000)
        campaigns = self.store.list_campaigns(limit=5000)
        families = self.store.list_families(limit=5000)
        infra = list(self.store.iter_infrastructure(limit=5000))
        iocs = list(self.store.iter_iocs(limit=20000))
        reports = list(self.store.iter_reports(limit=20000))

        passes = [
            ("actors", ActorCorrelator(
                alias_threshold=self.config.alias_match_threshold).correlate(
                    actors, now=now)),
            ("campaigns", CampaignCorrelator().correlate(campaigns, now=now)),
            ("malware", MalwareCorrelator().correlate(families, now=now)),
            ("infrastructure", InfrastructureCorrelator(
                min_signals=self.config.min_overlap_signals).correlate(
                    infra, now=now)),
            ("iocs", IOCCorrelator(
                min_confidence=self.config.correlation_min_confidence).correlate(
                    iocs, now=now)),
            ("reports", ReportCorrelator().correlate(reports, now=now)),
        ]
        merge_candidates: List[Dict[str, Any]] = []
        for name, res in passes:
            if res.relationships:
                self.store.save_relationships(res.relationships)
            counts[name] = len(res.relationships)
            merge_candidates.extend(res.candidates)
        if merge_candidates:
            self.store.kv_set("correlation", "merge_candidates", merge_candidates)
        counts["merge_candidates"] = len(merge_candidates)
        return counts

    # -- full run --------------------------------------------------------- #

    def run_all(self, *, providers: Optional[List[str]] = None,
                correlate: bool = True) -> OrchestrationResult:  # pragma: no cover
        start = time.time()
        out = OrchestrationResult()
        agg = IngestResult()
        provider_list = providers or self.config.available_providers()
        for provider in provider_list:
            ingestor = self.build_ingestor(provider)
            if ingestor is None:
                continue
            try:
                res = self._run_provider(provider, ingestor)
                agg.extend(res)
                out.providers_run.append(provider)
                out.errors.extend(res.errors)
            except Exception as exc:
                out.errors.append(f"{provider}: {exc}")
        stats = self.pipeline.process(agg)
        out.pipeline = stats.to_dict()
        if correlate:
            out.correlation = self.correlate()
        out.duration_seconds = time.time() - start
        return out

    def _run_provider(self, provider: str, ingestor) -> IngestResult:  # pragma: no cover
        if provider == "rss":
            return ingestor.run(feed_urls=self.config.default_rss_feeds,
                                store=self.store)
        if provider == "taxii":
            agg = IngestResult(provider="taxii")
            for root in self.config.taxii_roots:
                agg.extend(ingestor.run(api_root=root, store=self.store))
            return agg
        if provider == "cisa_kev" or provider == "cisa":
            return ingestor.run(store=self.store)
        return ingestor.run(store=self.store)

    def stats(self) -> Dict[str, Any]:
        return {"store": self.store.stats(), "attack": self.attack.stats(),
                "capec": self.capec.stats(),
                "providers_available": self.config.available_providers(),
                "cache": self.cache.stats()}


__all__ = ["Orchestrator", "OrchestrationResult"]
