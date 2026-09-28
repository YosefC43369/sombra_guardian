"""
threat_actor_intelligence.ingestion — public CTI collectors.

Each ingestor separates a PURE ``parse(...)`` (fixtures, offline, unit-tested)
from an I/O ``run(...)`` (polite conditional HTTP). All are passive, read-only,
public-source-only collectors; none bypass auth, ignore rate limits or fetch
non-public data (spec SECURITY BOUNDARIES). They emit a common ``IngestResult``
the pipeline resolves into stored entities.
"""

from .base import (HTTPClient, HTTPResponse, RateLimiter, IngestResult,
                   BaseIngestor, HAVE_HTTPX)
from .extract import extract, Extraction
from .rss_ingestor import RSSIngestor
from .stix_ingestor import STIXIngestor, parse_indicator_pattern
from .taxii_ingestor import TAXIIIngestor
from .vendor_ingestor import VendorIngestor, html_to_text
from .github_ingestor import GitHubIngestor
from .cisa_ingestor import CISAIngestor
from .nvd_ingestor import NVDIngestor
from .otx_ingestor import OTXIngestor
from .urlhaus_ingestor import URLhausIngestor
from .malwarebazaar_ingestor import MalwareBazaarIngestor

# Registry: provider name -> ingestor class, for the orchestrator to instantiate.
INGESTORS = {
    RSSIngestor.name: RSSIngestor,
    STIXIngestor.name: STIXIngestor,
    TAXIIIngestor.name: TAXIIIngestor,
    VendorIngestor.name: VendorIngestor,
    GitHubIngestor.name: GitHubIngestor,
    CISAIngestor.name: CISAIngestor,
    NVDIngestor.name: NVDIngestor,
    OTXIngestor.name: OTXIngestor,
    URLhausIngestor.name: URLhausIngestor,
    MalwareBazaarIngestor.name: MalwareBazaarIngestor,
}

__all__ = ["HTTPClient", "HTTPResponse", "RateLimiter", "IngestResult",
           "BaseIngestor", "HAVE_HTTPX", "extract", "Extraction",
           "RSSIngestor", "STIXIngestor", "parse_indicator_pattern",
           "TAXIIIngestor", "VendorIngestor", "html_to_text", "GitHubIngestor",
           "CISAIngestor", "NVDIngestor", "OTXIngestor", "URLhausIngestor",
           "MalwareBazaarIngestor", "INGESTORS"]
