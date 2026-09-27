"""
entity_fusion.engines.domain_engine — derive correlation keys from a domain or
subdomain record (canonical/punycode form, registrable base, homoglyph
skeleton), offline. Network collection (WHOIS/DNS/CT/Wayback) lives in the
enrichers; this engine only canonicalises and links what is already in the
record.
"""

from __future__ import annotations

from ..entity import Entity, EntityType, Evidence
from .. import normalization as norm
from .base import CorrelationEngine, EngineResult

# A pragmatic multi-label public-suffix shortlist so ``foo.co.uk`` yields the
# registrable base ``foo.co.uk`` rather than ``co.uk``. Not the full PSL — the
# enrichers can refine with a real list; this keeps the engine dependency-free.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.th", "in.th", "or.th", "ac.th",
    "com.au", "net.au", "org.au", "co.jp", "or.jp", "com.br", "com.cn",
    "co.il", "org.il", "com.sg", "co.nz", "co.za", "com.mx",
}


def registrable_base(domain: str) -> str:
    """Best-effort registrable domain (eTLD+1) using the shortlist above."""
    d = norm.canonical_domain(domain)
    if not d:
        return ""
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in _MULTI_LABEL_SUFFIXES:
        return ".".join(parts[-3:]) if len(parts) >= 3 else d
    if last3 in _MULTI_LABEL_SUFFIXES:
        return ".".join(parts[-4:]) if len(parts) >= 4 else d
    return last2


class DomainEngine(CorrelationEngine):
    name = "domain_engine"
    handles = (EntityType.DOMAIN, EntityType.SUBDOMAIN)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        canon = norm.canonical_domain(entity.value)
        if not canon:
            return result
        entity.normalized = canon
        result.derived["canonical_domain"] = canon
        base = registrable_base(canon)
        if base:
            result.derived["registrable_domain"] = base
            entity.add_alias(base)
        result.derived["domain_skeleton"] = norm.skeleton(canon)
        if canon != entity.value.strip().lower():
            # value differed from canonical (unicode/punycode/scheme noise)
            result.evidence.append(Evidence(
                kind="domain_canonicalized", value=canon, weight=0.0,
                note=f"canonicalized from {entity.value!r}"))
        # punycode / IDN homoglyph flag
        if canon.startswith("xn--") or "xn--" in canon:
            result.evidence.append(Evidence(
                kind="idn_domain", value=canon, weight=0.0,
                note="internationalized (punycode) domain — check for homoglyphs"))
        return result
