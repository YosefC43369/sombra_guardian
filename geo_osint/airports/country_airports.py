"""
geo_osint.airports.country_airports — country-level aviation aggregation.

Aggregates the airport database by country: counts, the airports with the most
runway capacity / an IATA code (a proxy for scheduled service), a bounding box of
a country's aviation footprint and a GeoJSON layer. Uses the engine's streaming
iterator so a very large database is scanned once, bounded by the engine's cap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models.airport import Airport
from ..models.geofence import BoundingBox
from .airport_engine import AirportEngine


@dataclass
class CountryAviation:
    country_code: str
    total: int = 0
    with_iata: int = 0
    airports: List[Airport] = field(default_factory=list)

    @property
    def hubs(self) -> List[Airport]:
        """Airports carrying an IATA code (proxy for scheduled passenger service)."""
        return [a for a in self.airports if a.iata]

    def bounding_box(self) -> Optional[BoundingBox]:
        pts = [(a.coordinate.latitude, a.coordinate.longitude)
               for a in self.airports if a.has_fix]
        return BoundingBox.from_points(pts) if pts else None

    def to_dict(self) -> Dict[str, Any]:
        bb = self.bounding_box()
        return {"country_code": self.country_code, "total": self.total,
                "with_iata": self.with_iata,
                "hubs": [a.code for a in self.hubs],
                "bounding_box": bb.to_dict() if bb else None}


class CountryAirportsEngine:
    def __init__(self, engine: Optional[AirportEngine] = None) -> None:
        self._engine = engine or AirportEngine()

    def for_country(self, country_code: str, limit: int = 1000) -> CountryAviation:
        cc = (country_code or "").strip().upper()
        agg = CountryAviation(country_code=cc)
        for ap in self._engine.by_country(cc, limit=limit):
            agg.total += 1
            if ap.iata:
                agg.with_iata += 1
            agg.airports.append(ap)
        return agg

    def counts_by_country(self, cap: int = 100_000) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        n = 0
        for ap in self._engine._iter_airports():
            if ap.country:
                counts[ap.country] = counts.get(ap.country, 0) + 1
            n += 1
            if n >= cap:
                break
        return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
