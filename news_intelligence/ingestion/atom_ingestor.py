"""
news_intelligence.ingestion.atom_ingestor — public Atom feed ingestion.

Atom and RSS share one normalized item shape (see ``feedparse``), so the Atom
ingestor reuses the RSS item→``Article`` normalization and only differs in provider
name and in preferring the Atom ``<content>`` element for the body. Kept as a
distinct ingestor so the provider registry, scheduler stats and per-format
overrides can address Atom feeds specifically.
"""

from __future__ import annotations

from typing import Any, Optional

from ..models.source import NewsSource
from .base import IngestResult
from .rss_ingestor import RSSIngestor


class AtomIngestor(RSSIngestor):
    name = "atom"

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "") -> IngestResult:
        result = super().parse(raw, source=source, feed_url=feed_url)
        result.provider = self.name
        return result


__all__ = ["AtomIngestor"]
