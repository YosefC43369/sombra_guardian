"""
news_intelligence.ingestion.vendor_ingestor — security-vendor research blogs.

A vendor blog RSS ingestor that classifies its output as vendor research (higher
evidence weight than a generic news feed) and can optionally fetch each item's full
page and run the readability + metadata + schema.org parsers to enrich the body,
canonical URL, author and publication date beyond what the feed carries.

Full-page enrichment is opt-in (``enrich=True``) and rate-limited; the pure feed
parse works entirely offline for tests.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from ..parsing.readability import ReadabilityExtractor
from ..parsing.metadata_parser import MetadataParser
from ..parsing.schema_parser import SchemaParser
from ..parsing.publication_parser import parse_date
from ..parsing.author_parser import AuthorParser
from .base import IngestResult
from .rss_ingestor import RSSIngestor


class VendorIngestor(RSSIngestor):
    name = "vendor"
    default_source_class = "vendor"

    def __init__(self, *, enrich: bool = False, **kw):
        super().__init__(**kw)
        self.enrich = enrich
        self._read = ReadabilityExtractor()
        self._meta = MetadataParser()
        self._schema = SchemaParser()
        self._author = AuthorParser()

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "") -> IngestResult:
        if source is None:
            source = NewsSource(name=feed_url or self.name,
                                category=SourceCategory.VENDOR_SECURITY_BLOG,
                                reliability_class=ReliabilityClass.VENDOR_RESEARCH,
                                rss_url=feed_url)
        result = super().parse(raw, source=source, feed_url=feed_url)
        result.provider = self.name
        return result

    def enrich_article(self, article, html: str):
        """Enrich an article in place from its fetched HTML page."""
        meta = self._meta.parse(html)
        schema = self._schema.parse(html)
        body = self._read.extract(html)
        if body and len(body) > len(article.body):
            article.body = body[: self.max_summary * 6]
        if not article.canonical_url:
            article.canonical_url = (meta.get("canonical_url")
                                     or schema.get("canonical_url") or "")
        best_author = (schema.get("author") or meta.get("author")
                       or article.author)
        if best_author:
            article.authors = self._author.parse(best_author) or article.authors
            article.author = article.authors[0] if article.authors else article.author
        pub = parse_date(schema.get("published", "")) or \
            parse_date(meta.get("published", ""))
        if pub:
            article.publication_date = pub
        if not article.language:
            article.language = (schema.get("language")
                                or meta.get("language") or "")[:5]
        for kw in (schema.get("keywords") or []) + (meta.get("tags") or []):
            if kw and kw not in article.tags:
                article.tags.append(kw)
        return article

    def run(self, *, source: NewsSource, store=None) -> IngestResult:  # pragma: no cover
        result = super().run(source=source, store=store)
        if self.enrich and result.articles:
            for art in result.articles:
                if not art.url:
                    continue
                resp, _ = self.conditional_get(art.url, store=store)
                if resp.status == 200:
                    try:
                        self.enrich_article(art, resp.text)
                    except Exception as exc:
                        result.errors.append(f"enrich {art.url}: {exc}")
        return result


__all__ = ["VendorIngestor"]
