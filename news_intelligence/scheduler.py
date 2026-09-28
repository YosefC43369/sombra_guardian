"""
news_intelligence.scheduler — recurring, incremental ingestion scheduling.

Decides which feeds are due for a poll (per-feed interval + failure backoff), runs the
orchestrator over just those, and records per-feed success/failure so a flapping source
backs off instead of hammering. Stateless between calls except through the store, so it
survives restarts and is safe to drive from ``app.py``'s job loop or an external cron.

This does not start its own thread; a caller ticks ``run_due`` on whatever cadence it
likes (the config's ``poll_interval_seconds`` is the natural default).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .configuration import NewsIntelConfig, get_config, default_sources
from .storage.sqlite_store import SQLiteStore
from .models.feed import Feed, FeedFormat
from .models.source import NewsSource
from .orchestrator import Orchestrator

_log = logging.getLogger("news_intelligence.scheduler")


@dataclass
class SchedulerTick:
    due_feeds: int = 0
    polled: int = 0
    failed: int = 0
    articles: int = 0
    errors: List[str] = field(default_factory=list)
    at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


class Scheduler:
    def __init__(self, *, config: Optional[NewsIntelConfig] = None,
                 store: Optional[SQLiteStore] = None,
                 orchestrator: Optional[Orchestrator] = None):
        self.config = config or get_config()
        self.store = store or SQLiteStore(self.config.db_path)
        self.orchestrator = orchestrator or Orchestrator(config=self.config,
                                                         store=self.store)

    # -- feed registry management ---------------------------------------- #
    def ensure_feeds(self) -> int:
        """Create a Feed per enabled source that lacks one."""
        sources = self.store.list_sources(enabled_only=True)
        if not sources:
            self.store.save_sources(default_sources())
            sources = self.store.list_sources(enabled_only=True)
        existing = {f.url for f in self.store.list_feeds()}
        created = 0
        for s in sources:
            if s.rss_url and s.rss_url not in existing:
                self.store.save_feed(Feed(
                    url=s.rss_url, source_id=s.source_id, provider="rss",
                    poll_interval=s.update_frequency or self.config.poll_interval_seconds))
                created += 1
        return created

    def due_feeds(self, *, now: Optional[float] = None) -> List[Feed]:
        now = now or time.time()
        return [f for f in self.store.list_feeds(enabled_only=True) if f.due(now=now)]

    # -- one scheduled tick ---------------------------------------------- #
    def run_due(self, *, now: Optional[float] = None, limit: int = 0
                ) -> SchedulerTick:  # pragma: no cover - network
        now = now or time.time()
        self.ensure_feeds()
        due = self.due_feeds(now=now)
        if limit:
            due = due[:limit]
        tick = SchedulerTick(due_feeds=len(due), at=now)
        source_by_id = {s.source_id: s for s in self.store.list_sources()}
        collected = []
        for feed in due:
            src = source_by_id.get(feed.source_id) or NewsSource(
                name=feed.url, rss_url=feed.url)
            from .providers import provider_for_category
            provider = provider_for_category(src.category, config=self.config)
            try:
                res = provider.collect(src, store=self.store)
                if res.errors:
                    feed.record_failure("; ".join(res.errors), now=now)
                    tick.failed += 1
                    tick.errors.extend(res.errors)
                else:
                    feed.record_success(items=len(res.articles), now=now)
                    tick.polled += 1
                    collected.extend(res.articles)
            except Exception as exc:
                feed.record_failure(str(exc), now=now)
                tick.failed += 1
                tick.errors.append(f"{feed.url}: {exc}")
            self.store.save_feed(feed)

        if collected:
            oc = self.orchestrator.run_cycle(articles=collected, now=now)
            tick.articles = oc.articles_collected
            tick.errors.extend(oc.errors)
        self.store.kv_set("scheduler", "last_tick", tick.to_dict())
        return tick

    def status(self) -> Dict[str, Any]:
        feeds = self.store.list_feeds()
        return {
            "feeds": len(feeds),
            "enabled": sum(1 for f in feeds if f.enabled),
            "failing": sum(1 for f in feeds if f.consecutive_failures > 0),
            "last_tick": self.store.kv_get("scheduler", "last_tick"),
        }


__all__ = ["Scheduler", "SchedulerTick"]
