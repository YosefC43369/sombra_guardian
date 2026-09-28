"""
geo_osint.transport.seaport_engine — public seaport intelligence (spec §7).

Typed access to the curated public seaport table (container/oil/passenger/inland/
ferry terminals) as :class:`~geo_osint.models.infrastructure.Facility` records with
administrative mapping and coordinates, plus nearest-port and by-country queries.
Extendable at runtime from OSM harbour tags or public port-authority data.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..data import seaports as _seaports
from ..models.coordinate import Coordinate
from ..models.evidence import Evidence
from ..models.infrastructure import Facility, FacilityType
from ..models.observation import GeoObservation, LocationType


class SeaportEngine:
    def _to_facility(self, rec: Dict[str, Any]) -> Facility:
        return Facility(
            name=rec["name"], facility_type=FacilityType.SEAPORT,
            coordinate=rec["coordinate"], city="", country_code=rec["country_code"],
            identifiers={"unlocode": rec.get("unlocode", "")},
            source="curated:public-port-refs",
            metadata={"port_type": rec.get("type", "")})

    def all(self) -> List[Facility]:
        return [self._to_facility(r) for r in _seaports.all_ports()]

    def by_country(self, country_code: str) -> List[Facility]:
        return [self._to_facility(r) for r in _seaports.by_country(country_code)]

    def find(self, name: str) -> List[Facility]:
        n = (name or "").strip().lower()
        return [self._to_facility(r) for r in _seaports.all_ports()
                if n in r["name"].lower()]

    def nearest(self, coord: Coordinate, limit: int = 5,
                max_km: float = 1000.0) -> List[Tuple[Facility, float]]:
        scored = []
        for r in _seaports.all_ports():
            d = coord.distance_km(r["coordinate"], method="haversine")
            if d <= max_km:
                scored.append((self._to_facility(r), round(d, 3)))
        scored.sort(key=lambda t: t[1])
        return scored[:limit]

    def to_observation(self, facility: Facility) -> GeoObservation:
        ev = Evidence(source="curated:public-port-refs",
                      claim=f"seaport {facility.name} in {facility.country_code}",
                      confidence=0.8, precision="port-area (public)",
                      limitations="Port coordinate is the general terminal area, "
                                  "public reference only.")
        return GeoObservation(
            entity_id=facility.name, location_type=LocationType.SEAPORT,
            coordinate=facility.coordinate, source="seaports",
            country_code=facility.country_code, evidence=[ev],
            metadata=facility.metadata)

    def to_feature_collection(self) -> Dict[str, Any]:
        feats = [f.to_geojson_feature() for f in self.all()]
        return {"type": "FeatureCollection",
                "features": [f for f in feats if f is not None]}
