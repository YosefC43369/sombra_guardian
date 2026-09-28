"""
news_intelligence.providers — source-category → ingestor binding + registry.

Maps a ``SourceCategory`` to the provider that knows how to collect it, so the
orchestrator can iterate sources and dispatch each to the right collector without
hard-coding ingestor choices. A provider that needs a key it does not have reports
``is_available() == False`` and is skipped — graceful degradation.
"""

from ..models.source import SourceCategory
from .base import BaseProvider
from .rss_provider import RSSProvider
from .vendor_provider import VendorProvider
from .github_provider import GitHubProvider
from .nvd_provider import NVDProvider
from .cisa_provider import CISAProvider, CISAKEVProvider
from .cert_provider import CERTProvider
from .blog_provider import BlogProvider, PodcastProvider


# category -> provider class
CATEGORY_PROVIDERS = {
    SourceCategory.VENDOR_SECURITY_BLOG: VendorProvider,
    SourceCategory.THREAT_INTEL_VENDOR: VendorProvider,
    SourceCategory.RESEARCH_BLOG: BlogProvider,
    SourceCategory.OPEN_SOURCE_PROJECT: RSSProvider,
    SourceCategory.NEWS_ORGANIZATION: RSSProvider,
    SourceCategory.CYBERSECURITY_PODCAST: PodcastProvider,
    SourceCategory.GITHUB_SECURITY_FEED: GitHubProvider,
    SourceCategory.GOVERNMENT_ADVISORY: CISAProvider,
    SourceCategory.CERT: CERTProvider,
    SourceCategory.PUBLIC_STIX_FEED: RSSProvider,
    SourceCategory.UNKNOWN: RSSProvider,
}


def provider_for_category(category, **kw) -> BaseProvider:
    cls = CATEGORY_PROVIDERS.get(SourceCategory.coerce(category), RSSProvider)
    return cls(**kw)


__all__ = [
    "BaseProvider", "RSSProvider", "VendorProvider", "GitHubProvider",
    "NVDProvider", "CISAProvider", "CISAKEVProvider", "CERTProvider",
    "BlogProvider", "PodcastProvider", "CATEGORY_PROVIDERS",
    "provider_for_category",
]
