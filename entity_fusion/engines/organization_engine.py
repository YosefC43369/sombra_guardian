"""
entity_fusion.engines.organization_engine — canonicalize an organisation record
and derive a comparison key that tolerates the usual suffix/legal-form noise
(``Acme, Inc.`` ≡ ``Acme LLC`` ≡ ``ACME``). Offline only; the public-profile /
WHOIS-org / GitHub-org fetches are enrichers.
"""

from __future__ import annotations

import re

from ..entity import Entity, EntityType, Evidence
from .. import normalization as norm
from .base import CorrelationEngine, EngineResult

# Legal-form and boilerplate tokens dropped before building the org key.
_ORG_STOPWORDS = {
    "inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation",
    "co", "company", "gmbh", "ag", "sa", "srl", "bv", "plc", "pllc", "llp",
    "group", "holdings", "holding", "the",
}


def org_key(name: str) -> str:
    """A canonical organisation key: normalised, stop-words removed, joined."""
    norm_name = norm.normalize_text(name, casefold=True, fold_confusables=True)
    tokens = [t for t in re.split(r"[^a-z0-9]+", norm_name)
              if t and t not in _ORG_STOPWORDS]
    return "".join(tokens)


class OrganizationEngine(CorrelationEngine):
    name = "organization_engine"
    handles = (EntityType.ORGANIZATION,)

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        key = org_key(entity.value)
        if key:
            entity.normalized = key
            result.derived["org_key"] = key
            result.derived["org_skeleton"] = norm.skeleton(entity.value)
        for meta_key in ("website", "url", "homepage"):
            site = entity.metadata.get(meta_key)
            if site:
                result.derived.setdefault("website", norm.canonical_url(str(site)))
                break
        if not key:
            result.evidence.append(Evidence(
                kind="org_unnormalizable", value=entity.value, weight=-0.05,
                note="organisation name reduced to empty key"))
        return result
