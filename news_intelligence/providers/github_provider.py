"""news_intelligence.providers.github_provider — GitHub security advisories provider."""
from __future__ import annotations
from ..ingestion.github_blog_ingestor import GitHubBlogIngestor
from .base import BaseProvider


class GitHubProvider(BaseProvider):
    name = "github"
    ingestor_cls = GitHubBlogIngestor


__all__ = ["GitHubProvider"]
