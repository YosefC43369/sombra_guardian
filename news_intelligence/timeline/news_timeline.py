"""
news_intelligence.timeline.news_timeline — the general news timeline builder.

Builds a chronology of the whole corpus or of any entity value from stored articles.
Every entry is dated by its article's publication date and cites that article, so the
timeline is evidence-dated end to end. ``build_for_value`` resolves an entity value
(actor/malware/CVE/org/country) to the articles that mention it and orders them.
"""

from __future__ import annotations

import time
from typing import List, Optional

from ..models.article import Article
from ..models.entity import EntityType, normalize_value
from .base import Timeline, TimelineEntry, BaseTimelineBuilder


class NewsTimelineBuilder(BaseTimelineBuilder):
    subject_type = "news"

    def build_corpus(self, *, since: float = 0.0, limit: int = 500) -> Timeline:
        tl = Timeline(subject="corpus", subject_type=self.subject_type)
        for a in self.store.iter_articles(since=since, limit=limit):
            tl.add(self._entry(a, a.title))
        return tl

    def build_for_value(self, value: str, *, entity_type: str = "",
                        since: float = 0.0) -> Timeline:
        et = EntityType.coerce(entity_type) if entity_type else None
        norm = normalize_value(et, value) if et else value
        article_ids = self.store.articles_for_entity(
            value=norm, entity_type=(et.value if et else ""), since=since)
        tl = Timeline(subject=norm, subject_type=entity_type or self.subject_type)
        for aid in article_ids:
            a = self.store.get_article(aid)
            if a is not None:
                tl.add(self._entry(a, f"{norm} reported"))
        return tl

    def _entry(self, a: Article, label: str) -> TimelineEntry:
        return TimelineEntry(
            ts=a.publication_date or a.ingestion_date, label=label,
            article_id=a.article_id, source=a.source_domain or a.source_name,
            title=a.title, kind=self.subject_type,
            detail={"url": a.canonical_url or a.url})

    def new_vs_historical(self, timeline: Timeline, *, days: int = 7,
                          now: Optional[float] = None) -> dict:
        now = now or time.time()
        cutoff = now - days * 86400
        return {"new": [e.to_dict() for e in timeline.new_since(cutoff)],
                "historical": [e.to_dict() for e in timeline.historical(cutoff)]}


__all__ = ["NewsTimelineBuilder"]
