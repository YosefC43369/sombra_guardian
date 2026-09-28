"""
news_intelligence.ingestion.github_blog_ingestor — GitHub security advisories/releases.

Two shapes:
  * Atom mode — the public GitHub Security Advisories atom feed
    (github.com/advisories.atom), parsed as community/security-feed articles.
  * API mode — the GitHub REST advisories/releases JSON (needs GITHUB_TOKEN for a
    higher rate limit; works unauthenticated at a low rate), parsed into articles
    with the advisory GHSA id, severity and affected package recorded in detail.

Repository references in advisory text become REPOSITORY entity mentions downstream.
Pure parse for both shapes.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from ..models.article import Article, content_hash
from ..models.source import NewsSource, SourceCategory, ReliabilityClass
from ..models.evidence import SourceClass
from ..parsing.publication_parser import parse_date
from .base import BaseIngestor, IngestResult
from .rss_ingestor import RSSIngestor

ADVISORIES_ATOM = "https://github.com/advisories.atom"
ADVISORIES_API = "https://api.github.com/advisories"


class GitHubBlogIngestor(RSSIngestor):
    name = "github"
    default_source_class = "community"

    def parse(self, raw: Any, *, source: Optional[NewsSource] = None,
              feed_url: str = "") -> IngestResult:
        if source is None:
            source = NewsSource(name="GitHub Security Advisories",
                                category=SourceCategory.GITHUB_SECURITY_FEED,
                                reliability_class=ReliabilityClass.COMMUNITY_BLOG,
                                rss_url=feed_url or ADVISORIES_ATOM)
        result = super().parse(raw, source=source, feed_url=feed_url)
        result.provider = self.name
        return result

    def parse_api(self, raw: Any) -> IngestResult:
        """Parse the GitHub advisories REST JSON array."""
        text = (raw.decode("utf-8", "replace")
                if isinstance(raw, (bytes, bytearray)) else str(raw))
        result = IngestResult(provider=self.name)
        try:
            items = json.loads(text)
        except Exception as exc:
            result.errors.append(f"gh api json: {exc}")
            return result
        source = NewsSource(name="GitHub Security Advisories",
                            category=SourceCategory.GITHUB_SECURITY_FEED,
                            reliability_class=ReliabilityClass.COMMUNITY_BLOG,
                            website="https://github.com/advisories")
        for adv in (items if isinstance(items, list) else []):
            ghsa = adv.get("ghsa_id", "")
            summary = adv.get("summary", "") or adv.get("description", "")
            url = adv.get("html_url", "") or f"https://github.com/advisories/{ghsa}"
            published = parse_date(adv.get("published_at", "")) or time.time()
            cves = [adv.get("cve_id")] if adv.get("cve_id") else []
            art = Article(
                title=f"{ghsa}: {summary[:120]}" if ghsa else summary[:140],
                url=url, canonical_url=url,
                summary=summary[: self.max_summary], source_name=source.name,
                source_id=source.source_id, source_domain=source.domain,
                source_class=SourceClass.COMMUNITY, language="en",
                publication_date=published,
                tags=["ghsa", adv.get("severity", "")],
                content_hash=content_hash(ghsa or url, summary, "github.com"),
                detail={"ghsa_id": ghsa, "severity": adv.get("severity", ""),
                        "cve": adv.get("cve_id", ""),
                        "cwes": [c.get("cwe_id") for c in adv.get("cwes", []) or []]})
            # seed the CVE mention directly from the structured advisory
            if adv.get("cve_id"):
                art.cve_mentions = [adv["cve_id"].upper()]
            art.evidence = [art.as_evidence().to_dict()]
            result.articles.append(art)
            result.fetched += 1
        return result

    def run(self, *, source: Optional[NewsSource] = None, store=None,
            use_api: bool = False) -> IngestResult:  # pragma: no cover
        result = IngestResult(provider=self.name)
        if use_api:
            headers = {"Accept": "application/vnd.github+json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            resp = self.http.get(ADVISORIES_API, headers=headers)
            if resp.status != 200:
                result.errors.append(f"{ADVISORIES_API}: HTTP {resp.status}")
                return result
            return self.parse_api(resp.body)
        url = (source.rss_url if source and source.rss_url else ADVISORIES_ATOM)
        resp, _ = self.conditional_get(url, store=store)
        if resp.not_modified:
            result.not_modified = True
            return result
        if resp.status != 200:
            result.errors.append(f"{url}: HTTP {resp.status}")
            return result
        return self.parse(resp.body, source=source, feed_url=url)


__all__ = ["GitHubBlogIngestor", "ADVISORIES_ATOM", "ADVISORIES_API"]
