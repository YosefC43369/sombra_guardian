"""
news_intelligence.ingestion.podcast_ingestor — cybersecurity podcast feeds.

Podcast RSS feeds are ordinary RSS with iTunes/enclosure extensions. This ingestor
parses episode title + show-notes (the ``<description>`` / ``itunes:summary``) into
articles, discards the audio enclosure (the engine analyses text, not audio), and
classifies output as research-grade discussion. The episode page/link is preserved
as the primary source. Pure feed parse.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from .base import IngestResult
from .rss_ingestor import RSSIngestor

_ITUNES_SUMMARY_RE = re.compile(
    r"<itunes:summary>(.*?)</itunes:summary>", re.IGNORECASE | re.DOTALL)


class PodcastIngestor(RSSIngestor):
    name = "podcast"
    default_source_class = "research"

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "") -> IngestResult:
        if source is None:
            source = NewsSource(name=feed_url or "Security Podcast",
                                category=SourceCategory.CYBERSECURITY_PODCAST,
                                reliability_class=ReliabilityClass.INDEPENDENT_RESEARCHER,
                                rss_url=feed_url)
        result = super().parse(raw, source=source, feed_url=feed_url)
        result.provider = self.name
        for art in result.articles:
            if "podcast" not in art.tags:
                art.tags.append("podcast")
        return result


__all__ = ["PodcastIngestor"]
