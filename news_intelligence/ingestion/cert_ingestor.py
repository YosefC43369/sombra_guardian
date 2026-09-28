"""
news_intelligence.ingestion.cert_ingestor — national/sector CERT advisory feeds.

RSS ingestor classifying output as CERT advisories (high evidence weight). Carries
the CERT's country so the Country Intelligence Profile can separate a national CERT's
activity from vendor or news coverage. Pure feed parse.
"""

from __future__ import annotations

from typing import Any, Optional

from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from .base import IngestResult
from .rss_ingestor import RSSIngestor


class CERTIngestor(RSSIngestor):
    name = "cert"
    default_source_class = "government"

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "", country: str = "") -> IngestResult:
        if source is None:
            source = NewsSource(name=feed_url or "CERT",
                                category=SourceCategory.CERT,
                                reliability_class=ReliabilityClass.CERT,
                                country=country, rss_url=feed_url)
        result = super().parse(raw, source=source, feed_url=feed_url)
        result.provider = self.name
        return result


__all__ = ["CERTIngestor"]
