"""
news_intelligence.extraction — pure, reusable entity extraction over article text.

Every extractor emits ``EntityMention`` objects and does no I/O. The composite
``EntityExtractor`` runs them all and deduplicates. Indicator parsing is delegated
to the Threat Actor Intelligence Engine's miner so the two engines never diverge on
how an IOC is canonicalized.
"""

from .base import BaseExtractor, context_of, HAVE_TAI_EXTRACT
from .ioc_extractor import IOCExtractor
from .url_extractor import URLExtractor
from .cve_extractor import CVEExtractor
from .mitre_extractor import MitreExtractor, HAVE_ATTACK
from .actor_extractor import ActorExtractor
from .malware_extractor import MalwareExtractor
from .organization_extractor import OrganizationExtractor
from .location_extractor import LocationExtractor
from .entity_extractor import EntityExtractor
from . import reference

__all__ = [
    "BaseExtractor", "context_of", "HAVE_TAI_EXTRACT", "HAVE_ATTACK",
    "IOCExtractor", "URLExtractor", "CVEExtractor", "MitreExtractor",
    "ActorExtractor", "MalwareExtractor", "OrganizationExtractor",
    "LocationExtractor", "EntityExtractor", "reference",
]
