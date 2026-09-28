"""
threat_actor_intelligence.correlation.campaign_correlation.

Links campaigns by shared malware families, shared infrastructure, shared IOCs,
shared attributed actors and overlapping techniques, and detects temporal
overlap (campaigns active in the same window sharing ≥1 hard signal). The output
distinguishes a strong hard-signal link (shared infra/IOC/malware) from a weak
technique-only co-occurrence via the relationship weight.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..models.campaign import Campaign
from .base import (CorrelationResult, build_relationship, correlation_assertion,
                   count_multiplier)

_ATTR_WEIGHT = {"malware_families": 0.65, "infrastructure": 0.85, "iocs": 0.8,
                "actors": 0.7, "techniques": 0.25}
_TECH_OVERLAP_MIN = 3


def _overlaps_in_time(a: Campaign, b: Campaign) -> bool:
    if not (a.first_observed and a.last_observed and b.first_observed
            and b.last_observed):
        return False
    return a.first_observed <= b.last_observed and b.first_observed <= a.last_observed


class CampaignCorrelator:
    def __init__(self, *, min_weight: float = 0.3):
        self.min_weight = min_weight

    def correlate(self, campaigns: Sequence[Campaign],
                  *, now: Optional[float] = None) -> CorrelationResult:
        result = CorrelationResult()
        n = len(campaigns)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = campaigns[i], campaigns[j]
                shared: Dict[str, List[str]] = {}
                weight = 0.0
                for attr, w in _ATTR_WEIGHT.items():
                    common = sorted(set(getattr(a, attr, []) or [])
                                    & set(getattr(b, attr, []) or []))
                    if not common:
                        continue
                    if attr == "techniques" and len(common) < _TECH_OVERLAP_MIN:
                        continue
                    shared[attr] = common
                    weight += w * count_multiplier(len(common))
                if not shared:
                    continue
                if _overlaps_in_time(a, b):
                    weight += 0.1
                weight = round(min(1.0, weight), 4)
                if weight < self.min_weight:
                    continue
                signal = "; ".join(f"{k}: {', '.join(v[:4])}"
                                   for k, v in shared.items())
                if _overlaps_in_time(a, b):
                    signal += "; temporal overlap"
                evidence = list(a.evidence.refs) + list(b.evidence.refs)
                rel = build_relationship(
                    src_type="campaign", src_id=a.campaign_id, rel_type="overlaps",
                    dst_type="campaign", dst_id=b.campaign_id, signal=signal,
                    evidence=evidence, now=now, weight=weight)
                result.add_relationship(rel)
        if result.relationships:
            result.assertions.append(correlation_assertion(
                f"{len(result.relationships)} campaign overlap link(s).",
                "CORRELATED", result.relationships))
        return result


__all__ = ["CampaignCorrelator"]
