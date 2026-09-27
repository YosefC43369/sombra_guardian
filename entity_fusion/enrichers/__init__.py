"""
entity_fusion.enrichers — network enrichers (public sources) plus helpers to
register them as pipeline expanders.

All enrichers degrade to no-ops when the HTTP stack (httpx / osint) is absent, so
importing this package is always safe. ``register_default_expanders`` wires the
key-free enrichers into a ``RecursivePipeline`` so a caller gets a working
discovery graph out of the box; key-gated enrichers (OTX, urlscan pro, ipinfo
token) activate automatically when their env var is set.
"""

from __future__ import annotations

from typing import List

from .base import Enricher, EnrichmentResult, HAVE_HTTPX, HAVE_OSINT_HTTP
from .gravatar import GravatarEnricher
from .github import GitHubEnricher
from .crtsh import CrtShEnricher
from .dns import DNSEnricher
from .whois import WhoisEnricher
from .wayback import WaybackEnricher
from .ipinfo import IPInfoEnricher
from .urlscan import URLScanEnricher
from .alienvault import AlienVaultEnricher

__all__ = [
    "Enricher", "EnrichmentResult", "HAVE_HTTPX", "HAVE_OSINT_HTTP",
    "GravatarEnricher", "GitHubEnricher", "CrtShEnricher", "DNSEnricher",
    "WhoisEnricher", "WaybackEnricher", "IPInfoEnricher", "URLScanEnricher",
    "AlienVaultEnricher", "default_enrichers", "register_default_expanders",
]


def default_enrichers() -> List[Enricher]:
    return [
        GravatarEnricher(), GitHubEnricher(), CrtShEnricher(), DNSEnricher(),
        WhoisEnricher(), WaybackEnricher(), IPInfoEnricher(), URLScanEnricher(),
        AlienVaultEnricher(),
    ]


def register_default_expanders(pipeline) -> None:
    """Register every default enricher on a ``RecursivePipeline`` under each
    entity type it handles."""
    for enricher in default_enrichers():
        expander = enricher.as_expander()
        for etype in (enricher.handles or ()):
            pipeline.register(etype.value, expander)
