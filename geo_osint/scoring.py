"""
geo_osint.scoring — the explainable geographic-footprint score (spec §42).

This produces a *geographic relevance / footprint* score: how broad and how
well-evidenced an entity's public geographic footprint is. It is explicitly NOT a
"risk score" (spec §42 forbids that) — it never rates threat, danger or intent. It
simply summarises reach (how many countries/cities/infrastructure types), evidence
strength (mean confidence, source diversity) and spread (geographic extent), and it
returns the component breakdown so every number is explainable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .models.coordinate import haversine_km


@dataclass
class FootprintScore:
    score: float                       # 0..100, footprint breadth+evidence
    components: Dict[str, float] = field(default_factory=dict)
    explanation: List[str] = field(default_factory=list)
    disclaimer: str = ("Geographic-footprint score: measures breadth and evidence "
                       "of an entity's PUBLIC geographic footprint. It is NOT a risk, "
                       "threat or danger score.")

    def to_dict(self) -> Dict[str, Any]:
        return {"score": round(self.score, 2), "components": self.components,
                "explanation": self.explanation, "disclaimer": self.disclaimer}


class GeoFootprintScorer:
    def score(self, result: Any) -> FootprintScore:
        observations = list(result.observations.observations)
        placed = [o for o in observations if o.has_fix]
        countries = {o.country_code for o in observations if o.country_code}
        cities = {o.city for o in observations if o.city}
        types = {o.location_type.value for o in observations}
        sources = {e.source for o in observations for e in o.evidence}

        # Component sub-scores (each 0..1), then weighted to 0..100.
        reach = _sat(len(countries) / 5.0) * 0.4 + _sat(len(cities) / 8.0) * 0.6
        diversity = _sat(len(types) / 6.0)
        evidence = 0.0
        if observations:
            evidence = sum(o.confidence for o in observations) / len(observations)
        source_div = _sat(len(sources) / 5.0)
        spread = _sat(_max_extent_km(placed) / 5000.0)

        components = {
            "reach": round(reach, 3),
            "type_diversity": round(diversity, 3),
            "evidence_strength": round(evidence, 3),
            "source_diversity": round(source_div, 3),
            "geographic_spread": round(spread, 3),
        }
        weights = {"reach": 0.30, "type_diversity": 0.20,
                   "evidence_strength": 0.25, "source_diversity": 0.15,
                   "geographic_spread": 0.10}
        total = sum(components[k] * weights[k] for k in weights) * 100.0

        explanation = [
            f"{len(observations)} observation(s) across {len(countries)} "
            f"countr{'y' if len(countries) == 1 else 'ies'} and {len(cities)} "
            f"cit{'y' if len(cities) == 1 else 'ies'}.",
            f"{len(types)} distinct location type(s); "
            f"{len(sources)} independent source(s).",
            f"Mean evidence confidence {evidence:.2f}.",
        ]
        if placed:
            explanation.append(
                f"Geographic extent ~{_max_extent_km(placed):.0f} km.")
        return FootprintScore(score=total, components=components,
                              explanation=explanation)


def _sat(x: float) -> float:
    """Saturating 0..1 (diminishing returns above the reference count)."""
    return max(0.0, min(1.0, x))


def _max_extent_km(placed: List[Any]) -> float:
    coords = [o.coordinate for o in placed if o.coordinate]
    if len(coords) < 2:
        return 0.0
    best = 0.0
    # O(n^2) is fine for the bounded observation set of a single run.
    for i in range(len(coords)):
        for j in range(i + 1, len(coords)):
            d = haversine_km(coords[i].latitude, coords[i].longitude,
                             coords[j].latitude, coords[j].longitude)
            if d > best:
                best = d
    return best
