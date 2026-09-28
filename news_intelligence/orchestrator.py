"""
news_intelligence.orchestrator — the ingestion + correlation conductor.

Ties the collection layers together into one repeatable cycle:
  1. resolve the enabled sources (registry) to their providers;
  2. collect each (conditional fetch → parse) into ``IngestResult`` batches;
  3. run the pipeline (dedup, extract, evidence, persist, timeline);
  4. run the correlation + clustering passes and persist the derived campaigns,
     clusters and relationships;
  5. hand the fresh articles to the integration hub for peer-engine enrichment.

Every step is guarded so one bad source never sinks the run, and the whole cycle is
idempotent (re-running collects only what changed).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .configuration import NewsIntelConfig, get_config, default_sources
from .storage.sqlite_store import SQLiteStore
from .pipeline import Pipeline, PipelineResult
from .providers import provider_for_category
from .ingestion.base import HTTPClient, IngestResult
from .models.source import NewsSource
from .clustering.event_cluster import EventClusterer
from .clustering.campaign_cluster import CampaignClusterer
from .correlation.entity_correlation import EntityCorrelator
from .correlation.infrastructure_correlation import InfrastructureCorrelator
from .integration import IntegrationHub

_log = logging.getLogger("news_intelligence.orchestrator")


@dataclass
class OrchestrationResult:
    sources_attempted: int = 0
    sources_ok: int = 0
    articles_collected: int = 0
    pipeline: Optional[Dict[str, Any]] = None
    clusters: int = 0
    campaigns: int = 0
    relationships: int = 0
    integration: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


class Orchestrator:
    def __init__(self, *, config: Optional[NewsIntelConfig] = None,
                 store: Optional[SQLiteStore] = None,
                 pipeline: Optional[Pipeline] = None,
                 http: Optional[HTTPClient] = None):
        self.config = config or get_config()
        self.store = store or SQLiteStore(self.config.db_path)
        self.pipeline = pipeline or Pipeline(config=self.config, store=self.store)
        self.http = http
        self.integration = IntegrationHub(config=self.config)

    def _sources(self) -> List[NewsSource]:
        sources = self.store.list_sources(enabled_only=True)
        if not sources:
            sources = default_sources()
            self.store.save_sources(sources)
            sources = [s for s in sources if s.enabled]
        return sources

    def collect(self, *, sources: Optional[List[NewsSource]] = None
                ) -> List[IngestResult]:  # pragma: no cover - network
        results: List[IngestResult] = []
        for src in (sources or self._sources()):
            provider = provider_for_category(src.category, config=self.config,
                                             http=self.http)
            if not provider.is_available():
                continue
            try:
                res = provider.collect(src, store=self.store)
                results.append(res)
                src.mark_ingested()
                self.store.save_source(src)
            except Exception as exc:
                _log.warning("collect failed for %s: %s", src.name, exc)
                results.append(IngestResult(provider=provider.name,
                                            errors=[f"{src.name}: {exc}"]))
        return results

    def run_cycle(self, *, articles=None, now: Optional[float] = None
                  ) -> OrchestrationResult:
        """Run a full cycle. ``articles`` may be supplied to skip network collection
        (used by tests and by callers that already have parsed articles)."""
        start = time.time()
        now = now or start
        result = OrchestrationResult()

        if articles is None:  # pragma: no cover - network path
            batches = self.collect()
            result.sources_attempted = len(batches)
            result.sources_ok = sum(1 for b in batches if not b.errors)
            for b in batches:
                result.errors.extend(b.errors)
            collected = [a for b in batches for a in b.articles]
        else:
            collected = list(articles)
            result.sources_attempted = len({a.source_domain for a in collected})
            result.sources_ok = result.sources_attempted

        result.articles_collected = len(collected)
        pr = self.pipeline.process(collected, now=now)
        result.pipeline = pr.to_dict()
        result.errors.extend(pr.errors)

        # correlation + clustering over a recent window
        recent = self.store.list_articles(since=now - 30 * 86400, limit=5000)
        result.clusters = self._persist_clusters(recent, now)
        result.campaigns = self._persist_campaigns(recent, now)
        result.relationships = self._persist_relationships(recent, now)

        fresh = [a for a in (self.store.get_article(i) for i in pr.article_ids) if a]
        try:
            result.integration = self.integration.dispatch(fresh)
        except Exception as exc:
            result.errors.append(f"integration: {exc}")

        result.duration_seconds = round(time.time() - start, 3)
        self.store.kv_set("orchestrator", "last_run", {
            "at": now, "result": result.to_dict()})
        return result

    def _persist_clusters(self, articles, now) -> int:
        clusters = EventClusterer(
            window_hours=self.config.event_window_hours).cluster(articles)
        for c in clusters:
            self.store.save_cluster(c)
        return len(clusters)

    def _persist_campaigns(self, articles, now) -> int:
        camps = CampaignClusterer(now=now).build(articles)
        for c in camps:
            self.store.save_campaign(c)
        return len(camps)

    def _persist_relationships(self, articles, now) -> int:
        rels = EntityCorrelator(self.store, now=now,
                                min_confidence=self.config.correlation_min_confidence
                                ).correlate(articles)
        rels += InfrastructureCorrelator(self.store, now=now).correlate(articles)
        n = 0
        for r in rels:
            self.store.save_relationship(
                rel_id=r.rel_id, src_type=r.src_type, src_key=r.src_key,
                dst_type=r.dst_type, dst_key=r.dst_key, rel_type=r.rel_type,
                weight=r.weight, detail=r.to_dict())
            n += 1
        return n

    def last_run(self) -> Optional[Dict[str, Any]]:
        return self.store.kv_get("orchestrator", "last_run")


__all__ = ["Orchestrator", "OrchestrationResult"]
