"""
geo_osint.correlation.proximity — nearest public infrastructure (spec §26).

Given a point and a radius, find the nearest public features: airports, cities,
data centres, IXPs, universities, hospitals — whatever candidate providers are
wired in. Candidate sources are injected as callables (``() -> Iterable[item]``)
so the engine composes cleanly over the airport engine, the gazetteer and the
infrastructure engines without importing them all directly. Results carry the
distance and are sorted nearest-first, bounded by a configurable radius cap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from ..models.coordinate import Coordinate

CandidateProvider = Callable[[], Iterable[Any]]


@dataclass
class ProximityHit:
    item: Any
    category: str
    distance_km: float
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        coord = getattr(self.item, "coordinate", None)
        return {"category": self.category, "distance_km": self.distance_km,
                "name": self.name or _name_of(self.item),
                "coordinate": coord.to_dict() if coord else None}


@dataclass
class ProximityResult:
    origin: Coordinate
    radius_km: float
    hits: List[ProximityHit] = field(default_factory=list)

    def by_category(self, category: str) -> List[ProximityHit]:
        return [h for h in self.hits if h.category == category]

    def nearest(self, category: Optional[str] = None) -> Optional[ProximityHit]:
        pool = self.hits if category is None else self.by_category(category)
        return pool[0] if pool else None

    def to_dict(self) -> Dict[str, Any]:
        return {"origin": self.origin.to_dict(), "radius_km": self.radius_km,
                "count": len(self.hits), "hits": [h.to_dict() for h in self.hits]}


class ProximityEngine:
    def __init__(self, max_radius_km: float = 500.0) -> None:
        self._providers: Dict[str, CandidateProvider] = {}
        self._max_radius = max_radius_km

    def register(self, category: str, provider: CandidateProvider) -> "ProximityEngine":
        self._providers[category] = provider
        return self

    def search(self, origin: Coordinate, radius_km: float = 50.0,
               categories: Optional[List[str]] = None,
               limit_per_category: int = 10) -> ProximityResult:
        radius = min(radius_km, self._max_radius)
        result = ProximityResult(origin=origin, radius_km=radius)
        cats = categories or list(self._providers)
        for cat in cats:
            provider = self._providers.get(cat)
            if provider is None:
                continue
            hits: List[ProximityHit] = []
            for item in provider():
                coord = getattr(item, "coordinate", None)
                if coord is None:
                    continue
                d = origin.distance_km(coord, method="haversine")
                if d <= radius:
                    hits.append(ProximityHit(item, cat, round(d, 3), _name_of(item)))
            hits.sort(key=lambda h: h.distance_km)
            result.hits.extend(hits[:limit_per_category])
        result.hits.sort(key=lambda h: h.distance_km)
        return result

    def nearest_from(self, origin: Coordinate, candidates: Iterable[Any],
                     category: str = "item", limit: int = 5,
                     radius_km: Optional[float] = None) -> List[ProximityHit]:
        radius = radius_km if radius_km is not None else self._max_radius
        hits = []
        for item in candidates:
            coord = getattr(item, "coordinate", None)
            if coord is None:
                continue
            d = origin.distance_km(coord, method="haversine")
            if d <= radius:
                hits.append(ProximityHit(item, category, round(d, 3), _name_of(item)))
        hits.sort(key=lambda h: h.distance_km)
        return hits[:limit]


def _name_of(item: Any) -> str:
    for attr in ("name", "display_name", "code"):
        v = getattr(item, attr, None)
        if v:
            return str(v)
    return str(item)
