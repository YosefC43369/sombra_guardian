"""
news_intelligence.engine — the NewsIntelligenceEngine public API.

The single service-layer entry point used by the Telegram surface, ``app.py`` and
other Sombra Guardian engines. It composes the store, the extractor, the correlation /
clustering / timeline / trend / graph / report builders and the search engine, and
answers the spec's primary-objective questions:

    which threat actors appeared today?          -> top_entities('threat_actor')
    which campaigns discussed across vendors?     -> vendor_comparison / campaigns
    which CVEs are getting more attention?        -> trends('cve')
    which malware families appeared this week?    -> top_entities('malware_family')
    which countries/industries recur?             -> top_entities('country')
    which orgs have multiple independent reports?  -> corroboration
    which infra appears across unrelated sources?  -> cross_source_infrastructure
    which events are new vs historical?           -> events / timeline.new_vs_historical
    which reports corroborate each other?         -> related_articles / corroboration
    what changed since yesterday?                 -> whats_new

Every result carries evidence and confidence; nothing is fabricated and no attribution
is asserted beyond the cited public sources.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .configuration import NewsIntelConfig, get_config, default_sources
from .storage.sqlite_store import SQLiteStore
from .storage.cache_store import CacheStore
from .extraction.entity_extractor import EntityExtractor
from .pipeline import Pipeline, PipelineResult
from .models.article import Article
from .models.entity import EntityType
from .search import SearchEngine, FilterEngine, SearchQuery
from .trend import TrendEngine
from .correlation.article_correlation import ArticleCorrelator
from .correlation.infrastructure_correlation import InfrastructureCorrelator
from .correlation.report_correlation import ReportCorrelator
from .correlation.topic_correlation import TopicCorrelator
from .clustering.event_cluster import EventClusterer
from .clustering.campaign_cluster import CampaignClusterer
from .timeline.news_timeline import NewsTimelineBuilder
from .timeline._specific import (ActorTimelineBuilder, MalwareTimelineBuilder,
                                 CVETimelineBuilder, CampaignTimelineBuilder)
from .graph.news_graph import NewsGraphBuilder
from .graph.actor_graph import ActorGraphBuilder
from .graph.campaign_graph import CampaignGraphBuilder
from .graph.topic_graph import TopicGraphBuilder
from .reports import (render_report, DailyBriefBuilder, WeeklyBriefBuilder,
                      ActorReportBuilder, MalwareReportBuilder, CVEReportBuilder,
                      CampaignReportBuilder, ExecutiveReportBuilder)


class NewsIntelligenceEngine:
    def __init__(self, *, config: Optional[NewsIntelConfig] = None,
                 store: Optional[SQLiteStore] = None,
                 extractor: Optional[EntityExtractor] = None, attack=None):
        self.config = config or get_config()
        self.store = store or SQLiteStore(self.config.db_path)
        self.cache = CacheStore(self.config.cache_dir,
                                ttl=self.config.cache_ttl_seconds)
        self.extractor = extractor or EntityExtractor(attack=attack)
        self.pipeline = Pipeline(config=self.config, store=self.store,
                                 extractor=self.extractor)
        self.search_engine = SearchEngine(self.store)
        self.filters = FilterEngine(self.store)
        self.trends_engine = TrendEngine(
            window_days=self.config.trend_window_days,
            min_sample=self.config.trend_min_sample)

    # -- convenience: seed the default source registry -------------------- #
    def bootstrap_sources(self) -> int:
        return self.store.save_sources(default_sources())

    # -- ingestion -------------------------------------------------------- #
    def ingest_articles(self, articles: List[Article], *, now=None
                        ) -> PipelineResult:
        return self.pipeline.process(articles, now=now)

    # -- corpus queries --------------------------------------------------- #
    def _window(self, *, days: Optional[int] = None, hours: Optional[int] = None,
                now: Optional[float] = None) -> float:
        now = now or time.time()
        if hours is not None:
            return now - hours * 3600
        if days is not None:
            return now - days * 86400
        return 0.0

    def top_entities(self, entity_type: str, *, days: int = 1, limit: int = 10
                     ) -> List[Dict[str, Any]]:
        return self.store.entity_counts(entity_type, since=self._window(days=days),
                                        limit=limit)

    def actors_today(self, *, limit: int = 10) -> List[Dict[str, Any]]:
        return self.top_entities(EntityType.THREAT_ACTOR.value, days=1, limit=limit)

    def malware_this_week(self, *, limit: int = 10) -> List[Dict[str, Any]]:
        return self.top_entities(EntityType.MALWARE_FAMILY.value, days=7, limit=limit)

    def trends(self, kind: str = "cve", *, days: Optional[int] = None):
        articles = self.store.list_articles(
            since=self._window(days=(days or self.config.trend_window_days) * 2),
            limit=5000)
        te = TrendEngine(window_days=days or self.config.trend_window_days,
                         min_sample=self.config.trend_min_sample)
        fn = {"cve": te.cve_trends, "malware": te.malware_trends,
              "actor": te.actor_trends, "country": te.country_trends,
              "topic": te.topic_trends}.get(kind, te.cve_trends)
        return [t.to_dict() for t in fn(articles)]

    def cross_source_infrastructure(self, *, days: int = 7, min_domains: int = 2
                                    ) -> List[Dict[str, Any]]:
        articles = self.store.list_articles(since=self._window(days=days), limit=5000)
        return InfrastructureCorrelator(self.store).cross_source_iocs(
            articles, min_domains=min_domains)

    def events(self, *, days: int = 3, min_sources: int = 2) -> List[Dict[str, Any]]:
        articles = self.store.list_articles(since=self._window(days=days), limit=5000)
        clusters = EventClusterer(
            window_hours=self.config.event_window_hours).cluster(articles)
        return [c.to_dict() for c in clusters
                if c.independent_sources >= min_sources]

    def campaigns(self, *, days: int = 30) -> List[Dict[str, Any]]:
        articles = self.store.list_articles(since=self._window(days=days), limit=5000)
        return [c.to_dict() for c in CampaignClusterer().build(articles)]

    def related_articles(self, article_id: str, *, days: int = 30, top: int = 10):
        articles = self.store.list_articles(since=self._window(days=days), limit=5000)
        rels = ArticleCorrelator(self.store).related_to(article_id, articles, top=top)
        return [r.to_dict() for r in rels]

    def corroboration(self, entity_value: str, *, entity_type: str = "",
                      days: int = 30) -> Dict[str, Any]:
        ids = self.store.articles_for_entity(
            value=entity_value, entity_type=entity_type,
            since=self._window(days=days))
        arts = [a for a in (self.store.get_article(i) for i in ids) if a]
        return ReportCorrelator().corroboration(arts).to_dict()

    def vendor_comparison(self, subject: str, *, days: int = 30) -> Dict[str, Any]:
        articles = self.store.list_articles(since=self._window(days=days), limit=5000)
        return TopicCorrelator(self.store).vendor_comparison(articles, subject)

    def whats_new(self, *, days: int = 1) -> Dict[str, Any]:
        since = self._window(days=days)
        articles = self.store.list_articles(since=since, limit=2000)
        return {
            "window_days": days, "new_articles": len(articles),
            "new_actors": self.top_entities(EntityType.THREAT_ACTOR.value,
                                            days=days, limit=10),
            "new_cves": self.top_entities(EntityType.CVE.value, days=days, limit=10),
            "new_malware": self.top_entities(EntityType.MALWARE_FAMILY.value,
                                             days=days, limit=10),
            "emerging_trends": [t for t in self.trends("cve", days=days)
                                if t.get("direction") in ("emerging", "rising")][:10],
        }

    # -- search / filter -------------------------------------------------- #
    def search(self, text: str = "", **kw) -> List[Dict[str, Any]]:
        q = SearchQuery(text=text, **kw)
        return [h.to_dict() for h in self.search_engine.search(q)]

    def article(self, article_id: str) -> Optional[Dict[str, Any]]:
        a = self.store.get_article(article_id)
        return a.to_dict() if a else None

    # -- timelines -------------------------------------------------------- #
    def timeline(self, subject: str, *, kind: str = "news", fmt: str = "dict"):
        builder = {
            "actor": ActorTimelineBuilder, "malware": MalwareTimelineBuilder,
            "cve": CVETimelineBuilder, "campaign": CampaignTimelineBuilder,
        }.get(kind)
        if builder is not None:
            tl = builder(self.store).build(subject)
        else:
            tl = NewsTimelineBuilder(self.store).build_for_value(subject)
        return tl.to_dict()

    # -- graphs ----------------------------------------------------------- #
    def graph(self, *, kind: str = "news", subject: str = "", days: int = 14,
              fmt: str = "json") -> str:
        articles = self.store.list_articles(since=self._window(days=days), limit=5000)
        if kind == "actor" and subject:
            g = ActorGraphBuilder(self.store).build(subject, articles)
        elif kind == "campaign" and subject:
            camp = CampaignClusterer().build(articles)
            match = next((c for c in camp if c.name.lower() == subject.lower()), None)
            g = (CampaignGraphBuilder(self.store).build(match) if match
                 else NewsGraphBuilder(self.store).build(articles))
        elif kind == "topic":
            g = TopicGraphBuilder(self.store).build(articles)
        else:
            g = NewsGraphBuilder(self.store).build(articles)
        return g.export(fmt)

    # -- reports ---------------------------------------------------------- #
    def daily_brief(self, *, fmt: str = "dict", persist: bool = False):
        r = DailyBriefBuilder(self.store).build()
        if persist:
            self.store.save_report(r)
        return render_report(r, fmt=fmt)

    def weekly_brief(self, *, fmt: str = "dict", persist: bool = False):
        r = WeeklyBriefBuilder(self.store).build()
        if persist:
            self.store.save_report(r)
        return render_report(r, fmt=fmt)

    def actor_report(self, actor: str, *, fmt: str = "dict"):
        return render_report(ActorReportBuilder(self.store).build(actor), fmt=fmt)

    def malware_report(self, family: str, *, fmt: str = "dict"):
        return render_report(MalwareReportBuilder(self.store).build(family), fmt=fmt)

    def cve_report(self, cve: str, *, fmt: str = "dict"):
        return render_report(CVEReportBuilder(self.store).build(cve), fmt=fmt)

    def campaign_report(self, campaign: str, *, fmt: str = "dict"):
        return render_report(CampaignReportBuilder(self.store).build(campaign),
                             fmt=fmt)

    def executive_summary(self, *, fmt: str = "dict"):
        return render_report(ExecutiveReportBuilder(self.store).build(), fmt=fmt)

    # -- diagnostics ------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        return {"store": self.store.stats(), "cache": self.cache.stats(),
                "config": {"db_path": self.config.db_path,
                           "sources": len(self.store.list_sources())}}


__all__ = ["NewsIntelligenceEngine"]
