"""
news_intelligence.ingestion.rss_ingestor — public RSS/RDF security feed ingestion.

Parses an RSS 2.0 (or RDF) feed body into normalized ``Article`` objects, carrying
the source's identity, category and reliability so evidence weights correctly. Item
title+link preserve the primary-source URL; the summary is bounded. Entity
extraction is deferred to the pipeline (separation of concerns), so this parser is
pure and unit-tested offline against feed fixtures.
"""

from __future__ import annotations

import time
from typing import Any, List, Optional

from ..models.article import Article, content_hash
from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from ..models.evidence import source_class_for_category
from .base import BaseIngestor, IngestResult
from .feedparse import parse_feed, strip_html
from ..parsing.publication_parser import parse_date


class RSSIngestor(BaseIngestor):
    name = "rss"
    default_source_class = "feed"

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "") -> IngestResult:
        text = (raw.decode("utf-8", "replace")
                if isinstance(raw, (bytes, bytearray)) else str(raw))
        result = IngestResult(provider=self.name)
        source = source or NewsSource(name=feed_url or self.name,
                                      category=SourceCategory.NEWS_ORGANIZATION,
                                      reliability_class=ReliabilityClass.UNKNOWN,
                                      rss_url=feed_url)
        items = parse_feed(text)
        for it in items:
            art = self._item_to_article(it, source)
            if art is not None:
                result.articles.append(art)
                result.fetched += 1
        return result

    def _item_to_article(self, it: dict, source: NewsSource) -> Optional[Article]:
        title = strip_html(it.get("title", ""))
        link = (it.get("link") or "").strip()
        summary = strip_html(it.get("summary", ""))[: self.max_summary]
        body = strip_html(it.get("content", ""))[: self.max_summary * 6]
        if not title and not link:
            return None
        published = parse_date(it.get("published", "")) or time.time()
        tags = [t for t in (it.get("tags") or []) if t]
        art = Article(
            title=title or link, url=link, summary=summary, body=body,
            source_name=source.name, source_id=source.source_id,
            source_domain=source.domain,
            source_class=source_class_for_category(source.category),
            author=(it.get("author") or ""), language=source.language,
            publication_date=published, tags=tags,
            content_hash=content_hash(title, summary, source.domain),
        )
        art.evidence = [art.as_evidence().to_dict()]
        return art

    def run(self, *, source: NewsSource, store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        url = source.rss_url
        if not url:
            result.errors.append(f"{source.name}: no rss_url")
            return result
        resp, _ = self.conditional_get(url, store=store)
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{url}: HTTP {resp.status}")
            return result
        return self.parse(resp.body, source=source, feed_url=url)


__all__ = ["RSSIngestor"]
