"""
threat_actor_intelligence.correlation.actor_correlation.

Finds evidence-backed links *between actors* — shared malware families, shared
campaigns, shared infrastructure, overlapping ATT&CK technique sets — and surfaces
alias-based merge candidates (delegating to ``alias_resolution``, which never
merges automatically). An actor↔actor overlap is expressed as
``RelationType.OVERLAPS`` with the exact shared attributes named; it is *not*
attribution and never collapses two actors into one.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Sequence

from ..models.threat_actor import ThreatActor
from .alias_resolution import AliasResolver
from .base import (CorrelationResult, build_relationship, correlation_assertion,
                   count_multiplier)

# Shared-attribute strength for the overlap weight.
_ATTR_WEIGHT = {"malware_families": 0.6, "campaigns": 0.7, "infrastructure": 0.85,
                "techniques": 0.25, "software": 0.4}
_TECH_OVERLAP_MIN = 3     # require ≥3 shared techniques before it counts (TTPs are common)


class ActorCorrelator:
    def __init__(self, *, alias_threshold: float = 0.86,
                 min_weight: float = 0.3):
        self.alias_resolver = AliasResolver(threshold=alias_threshold)
        self.min_weight = min_weight

    def correlate(self, actors: Sequence[ThreatActor],
                  *, now: Optional[float] = None) -> CorrelationResult:
        result = CorrelationResult()
        n = len(actors)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = actors[i], actors[j]
                shared: Dict[str, List[str]] = {}
                weight = 0.0
                for attr, w in _ATTR_WEIGHT.items():
                    sa = set(getattr(a, attr, []) or [])
                    sb = set(getattr(b, attr, []) or [])
                    common = sorted(sa & sb)
                    if not common:
                        continue
                    if attr == "techniques" and len(common) < _TECH_OVERLAP_MIN:
                        continue
                    shared[attr] = common
                    weight += w * count_multiplier(len(common))
                weight = round(min(1.0, weight), 4)
                if not shared or weight < self.min_weight:
                    continue
                signal = "; ".join(f"{k}: {', '.join(v[:4])}"
                                   for k, v in shared.items())
                evidence = list(a.evidence.refs) + list(b.evidence.refs)
                rel = build_relationship(
                    src_type="actor", src_id=a.actor_id, rel_type="overlaps",
                    dst_type="actor", dst_id=b.actor_id, signal=signal,
                    evidence=evidence, now=now, weight=weight)
                result.add_relationship(rel)

        # alias merge candidates (suggestions only)
        objs = [(a.actor_id, a.all_names(), set(a.evidence.providers()))
                for a in actors]
        for cand in self.alias_resolver.suggest(objs):
            result.candidates.append(cand.to_dict())

        if result.relationships:
            result.assertions.append(correlation_assertion(
                f"{len(result.relationships)} actor overlap link(s) from shared "
                f"malware/campaign/infrastructure.", "CORRELATED",
                result.relationships))
        return result


__all__ = ["ActorCorrelator"]
