"""news_intelligence.providers.rss_provider — generic RSS/Atom/JSON feed provider."""
from __future__ import annotations
from ..ingestion.rss_ingestor import RSSIngestor
from .base import BaseProvider


class RSSProvider(BaseProvider):
    name = "rss"
    ingestor_cls = RSSIngestor


__all__ = ["RSSProvider"]
