"""
news_intelligence.ingestion — passive, public-source collectors.

Each ingestor cleanly separates a pure ``parse`` from I/O ``run``. All output is a
uniform ``IngestResult`` of normalized ``Article`` objects the pipeline resolves.
Read-only public collection: no auth bypass, no paywall bypass, no sample download.
"""

from .base import (HTTPClient, HTTPResponse, RateLimiter, IngestResult,
                   BaseIngestor, HAVE_HTTPX)
from .feedparse import parse_feed, parse_json_feed, HAVE_FEEDPARSER
from .rss_ingestor import RSSIngestor
from .atom_ingestor import AtomIngestor
from .json_feed import JSONFeedIngestor
from .vendor_ingestor import VendorIngestor
from .github_blog_ingestor import GitHubBlogIngestor
from .cisa_ingestor import CISAIngestor, CISAKEVIngestor
from .cert_ingestor import CERTIngestor
from .nvd_ingestor import NVDIngestor
from .exploit_blog_ingestor import ExploitBlogIngestor
from .podcast_ingestor import PodcastIngestor

# ingestor lookup by provider name, used by the orchestrator/scheduler
INGESTORS = {
    "rss": RSSIngestor,
    "atom": AtomIngestor,
    "json_feed": JSONFeedIngestor,
    "vendor": VendorIngestor,
    "github": GitHubBlogIngestor,
    "cisa": CISAIngestor,
    "cisa_kev": CISAKEVIngestor,
    "cert": CERTIngestor,
    "nvd": NVDIngestor,
    "exploit_blog": ExploitBlogIngestor,
    "podcast": PodcastIngestor,
}


def get_ingestor(provider: str, **kw) -> BaseIngestor:
    cls = INGESTORS.get(provider, RSSIngestor)
    return cls(**kw)


__all__ = [
    "HTTPClient", "HTTPResponse", "RateLimiter", "IngestResult", "BaseIngestor",
    "HAVE_HTTPX", "parse_feed", "parse_json_feed", "HAVE_FEEDPARSER",
    "RSSIngestor", "AtomIngestor", "JSONFeedIngestor", "VendorIngestor",
    "GitHubBlogIngestor", "CISAIngestor", "CISAKEVIngestor", "CERTIngestor",
    "NVDIngestor", "ExploitBlogIngestor", "PodcastIngestor",
    "INGESTORS", "get_ingestor",
]
