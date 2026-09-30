"""
cybersecurity_intelligence.engines.evidence_engine — corroboration & independence.

This engine turns a pile of individual, single-source claims into consolidated,
independence-aware claims. Two jobs:

1. **Consolidate.** Claims with the same ``claim_id`` (same subject + statement)
   are merged so their evidence accumulates on one claim instead of scattering.

2. **Judge independence.** The central discipline of the whole platform (spec
   §34, §35, §143): twenty sites re-printing one wire story are *not* twenty
   pieces of evidence. Citations are grouped so that:
     * all pure aggregators/feeds collapse into a single "secondary pool" that
       counts, collectively, as at most one independent source;
     * primary citations are grouped by their registrable source host, so two
       URLs on the same publisher count once;
   and the number of resulting groups is the *independent source count*.

A REPORTED claim is promoted to CORROBORATED only when it clears
``CORROBORATION_MIN_INDEPENDENT_SOURCES`` independent sources. Analyst INFERRED
claims are never promoted by corroboration (more agreeing reporters do not make an
inference an observation). Claims with no evidence become UNKNOWN.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse

from threat_actor_intelligence.models.evidence import EvidenceBundle, EvidenceRef

from ..constants import (
    CORROBORATION_MIN_INDEPENDENT_SOURCES,
    NON_INDEPENDENT_SOURCE_CLASSES,
)
from ..models.claim import Claim, ClaimType

_SECONDARY_POOL_KEY = "__secondary_pool__"


def registrable_host(url: str) -> str:
    """Best-effort registrable host from a URL: the last two DNS labels of the
    netloc (``research.checkpoint.com`` -> ``checkpoint.com``). Pure stdlib and
    intentionally simple — it only needs to collapse same-publisher URLs, not to
    be a full public-suffix parser."""
    if not url:
        return ""
    netloc = urlparse(url if "://" in url else "//" + url).netloc.lower()
    netloc = netloc.split("@")[-1].split(":")[0]
    labels = [l for l in netloc.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


class EvidenceEngine:
    """Consolidates claims and judges cross-source independence."""

    def __init__(self, *, min_independent: int = CORROBORATION_MIN_INDEPENDENT_SOURCES
                 ) -> None:
        self.min_independent = max(1, int(min_independent))

    # -- independence ------------------------------------------------------ #

    def independence_groups(self, bundle: EvidenceBundle) -> Dict[str, List[str]]:
        """Group citations into independent buckets. Returns {group_key:
        [provider,...]}. Aggregators/feeds share one bucket; primaries bucket by
        registrable host (or provider when no URL is present)."""
        groups: Dict[str, List[str]] = {}
        for ref in bundle:
            key = self._group_key(ref)
            groups.setdefault(key, [])
            if ref.provider and ref.provider not in groups[key]:
                groups[key].append(ref.provider)
        return groups

    def _group_key(self, ref: EvidenceRef) -> str:
        if ref.source_class.value in NON_INDEPENDENT_SOURCE_CLASSES:
            return _SECONDARY_POOL_KEY
        host = registrable_host(ref.source_url)
        return host or f"provider:{ref.provider or 'unknown'}"

    def independent_count(self, bundle: EvidenceBundle) -> int:
        return len(self.independence_groups(bundle))

    def independence_report(self, bundle: EvidenceBundle) -> Dict[str, Any]:
        groups = self.independence_groups(bundle)
        return {
            "independent_count": len(groups),
            "citation_count": len(bundle),
            "groups": {
                ("secondary_pool" if k == _SECONDARY_POOL_KEY else k): v
                for k, v in groups.items()
            },
            "meets_corroboration": len(groups) >= self.min_independent,
        }

    # -- consolidation ----------------------------------------------------- #

    def consolidate(self, claims: List[Claim]) -> List[Claim]:
        """Merge same-id claims, compute independence, and set the corroboration
        status. Returns a fresh list of consolidated claims."""
        merged: Dict[str, Claim] = {}
        for c in claims:
            key = c.claim_id
            if key in merged:
                merged[key].merge(c)
            else:
                merged[key] = c

        out: List[Claim] = []
        for c in merged.values():
            report = self.independence_report(c.evidence)
            c.detail["independence"] = report
            c.claim_type = self._classify(c, report["independent_count"])
            out.append(c)
        return out

    def _classify(self, claim: Claim, independent_count: int) -> ClaimType:
        """Set corroboration status from independence. Does not decide DISPUTED —
        that is the contradiction engine's output, applied downstream."""
        if len(claim.evidence) == 0:
            return ClaimType.UNKNOWN
        # Analyst inferences are never promoted by more agreeing reporters.
        if claim.claim_type is ClaimType.INFERRED:
            return ClaimType.INFERRED
        # A directly-observed fact stays observed regardless of source count.
        if claim.claim_type is ClaimType.OBSERVED:
            return ClaimType.OBSERVED
        if independent_count >= self.min_independent:
            return ClaimType.CORROBORATED
        return ClaimType.REPORTED

    def mark_disputed(self, claim: Claim) -> Claim:
        """Force a claim to DISPUTED (called by the facade when the contradiction
        engine flags its subject). Preserves the prior status in detail."""
        if claim.claim_type is not ClaimType.DISPUTED:
            claim.detail["status_before_dispute"] = claim.claim_type.value
            claim.claim_type = ClaimType.DISPUTED
        return claim


__all__ = ["EvidenceEngine", "registrable_host"]
