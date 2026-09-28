"""
news_intelligence.ingestion.json_feed — JSON Feed (jsonfeed.org) ingestion.

Parses a JSON Feed 1.x document into ``Article`` objects. Same normalization
discipline as the RSS/Atom ingestors; body prefers ``content_html`` (stripped) then
``content_text``. Pure parse; unit-tested against a JSON fixture.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from ..models.article import Article, content_hash
from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from ..models.evidence import source_class_for_category
from .base import BaseIngestor, IngestResult
from .feedparse import parse_json_feed, strip_html
from ..parsing.publication_parser import parse_date


class JSONFeedIngestor(BaseIngestor):
    name = "json_feed"

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "") -> IngestResult:
        text = (raw.decode("utf-8", "replace")
                if isinstance(raw, (bytes, bytearray)) else str(raw))
        result = IngestResult(provider=self.name)
        source = source or NewsSource(name=feed_url or self.name,
                                      category=SourceCategory.NEWS_ORGANIZATION,
                                      reliability_class=ReliabilityClass.UNKNOWN,
                                      rss_url=feed_url)
        for it in parse_json_feed(text):
            title = strip_html(it.get("title", ""))
            link = (it.get("link") or "").strip()
            if not title and not link:
                continue
            summary = strip_html(it.get("summary", ""))[: self.max_summary]
            body = strip_html(it.get("content", ""))[: self.max_summary * 6]
            published = parse_date(it.get("published", "")) or time.time()
            art = Article(
                title=title or link, url=link, summary=summary, body=body,
                source_name=source.name, source_id=source.source_id,
                source_domain=source.domain,
                source_class=source_class_for_category(source.category),
                author=it.get("author", ""), language=source.language,
                publication_date=published, tags=list(it.get("tags") or []),
                content_hash=content_hash(title, summary, source.domain))
            art.evidence = [art.as_evidence().to_dict()]
            result.articles.append(art)
            result.fetched += 1
        return result

    def run(self, *, source: NewsSource, store=None) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        resp, _ = self.conditional_get(source.rss_url, store=store)
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{source.rss_url}: HTTP {resp.status}")
            return result
        return self.parse(resp.body, source=source, feed_url=source.rss_url)


__all__ = ["JSONFeedIngestor"]
