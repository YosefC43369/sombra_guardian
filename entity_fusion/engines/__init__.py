"""
entity_fusion.engines — offline correlation engines (one per signal type) plus a
default registry.

Engines derive correlation keys, extract embedded identifiers and attach
evidence from a record without any network access. ``run_engines`` applies every
applicable engine to an entity and returns the union of discovered entities.
"""

from __future__ import annotations

from typing import Dict, List

from ..entity import Entity
from .base import CorrelationEngine, EngineResult
from .username_engine import UsernameEngine, generate_variants
from .email_engine import EmailEngine, BioEmailExtractor, gravatar_hash, extract_emails
from .phone_engine import PhoneEngine
from .crypto_engine import (CryptoEngine, BioWalletExtractor, detect_addresses,
                            classify_address)
from .domain_engine import DomainEngine, registrable_base
from .ip_engine import IPEngine
from .asn_engine import ASNEngine
from .certificate_engine import CertificateEngine
from .website_engine import WebsiteEngine
from .organization_engine import OrganizationEngine, org_key

__all__ = [
    "CorrelationEngine", "EngineResult",
    "UsernameEngine", "EmailEngine", "BioEmailExtractor", "PhoneEngine",
    "CryptoEngine", "BioWalletExtractor", "DomainEngine", "IPEngine",
    "ASNEngine", "CertificateEngine", "WebsiteEngine", "OrganizationEngine",
    "generate_variants", "gravatar_hash", "extract_emails", "detect_addresses",
    "classify_address", "registrable_base", "org_key",
    "default_engines", "run_engines",
]


def default_engines() -> List[CorrelationEngine]:
    """The standard engine set, in a sensible application order."""
    return [
        UsernameEngine(), EmailEngine(), PhoneEngine(), CryptoEngine(),
        DomainEngine(), IPEngine(), ASNEngine(), CertificateEngine(),
        WebsiteEngine(), OrganizationEngine(),
        BioEmailExtractor(), BioWalletExtractor(),
    ]


def run_engines(entity: Entity, engines: List[CorrelationEngine] = None) -> List[Entity]:
    """Apply engines to ``entity`` in place (folding derived metadata/evidence)
    and return every new entity discovered inside the record."""
    engines = engines if engines is not None else default_engines()
    discovered: List[Entity] = []
    for engine in engines:
        res = engine.run(entity)
        res.merge_into(entity)
        discovered.extend(res.entities)
    return discovered
