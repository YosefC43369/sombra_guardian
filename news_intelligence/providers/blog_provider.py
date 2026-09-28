"""news_intelligence.providers.blog_provider — research/exploit blog + podcast provider."""
from __future__ import annotations
from ..ingestion.exploit_blog_ingestor import ExploitBlogIngestor
from ..ingestion.podcast_ingestor import PodcastIngestor
from .base import BaseProvider


class BlogProvider(BaseProvider):
    name = "exploit_blog"
    ingestor_cls = ExploitBlogIngestor


class PodcastProvider(BaseProvider):
    name = "podcast"
    ingestor_cls = PodcastIngestor


__all__ = ["BlogProvider", "PodcastProvider"]
