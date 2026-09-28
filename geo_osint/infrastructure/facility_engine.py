"""
geo_osint.infrastructure.facility_engine — public facility inventory (spec §9, §35, §39-40).

A general engine for the public-infrastructure categories the spec enumerates
(government, hospital, university, power station, telecom exchange, industrial/
technology park, research center). It works two ways:

  * **offline / injected** — an in-memory registry the engine indexes and queries
    (nearest, in-bbox, by type/country), so callers can load any public dataset
    (Natural Earth, a national open-data export, a curated list) and query it
    without a network;
  * **online (OSM Overpass)** — when an HTTP client is supplied, it builds a
    read-only Overpass query for the public OSM tags of a category within a
    bounding box and parses the results into facilities. OSM's usage policy is
    respected (single bounded query, attribution recorded); nothing is scraped in
    bulk and only already-public map data is read (spec §17).

The specialised government/telecom engines are thin wrappers that fix the OSM tag
set for their category.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models.coordinate import Coordinate
from ..models.evidence import Evidence
from ..models.geofence import BoundingBox
from ..models.infrastructure import Facility, FacilityType
from ..models.observation import GeoObservation, LocationType
from ..storage.geo_index import GeoGridIndex

logger = logging.getLogger("modbot.geo_osint.facility")

# Category -> OSM tag filters for Overpass (public tags only).
_OSM_TAGS: Dict[FacilityType, List[str]] = {
    FacilityType.HOSPITAL: ['["amenity"="hospital"]'],
    FacilityType.UNIVERSITY: ['["amenity"="university"]'],
    FacilityType.GOVERNMENT: ['["office"="government"]', '["amenity"="townhall"]',
                              '["amenity"="courthouse"]'],
    FacilityType.POWER_STATION: ['["power"="plant"]'],
    FacilityType.SUBSTATION: ['["power"="substation"]'],
    FacilityType.TELECOM_EXCHANGE: ['["telecom"="exchange"]',
                                    '["man_made"="telephone_exchange"]'],
    FacilityType.DATACENTER: ['["telecom"="data_center"]',
                              '["office"="data_center"]'],
    FacilityType.INDUSTRIAL_PARK: ['["landuse"="industrial"]'],
    FacilityType.RESEARCH_CENTER: ['["amenity"="research_institute"]'],
}

_OVERPASS_URL = "https://overpass-api.de/api/interpreter"

_OSM_LIMITATION = (
    "Facility data is from public OpenStreetMap tags contributed by volunteers; "
    "presence, position and attributes are as-tagged and may be incomplete or "
    "approximate. Public listing only — no internal layout is inferred.")


class FacilityEngine:
    def __init__(self, overpass_url: str = _OVERPASS_URL) -> None:
        self._registry: List[Facility] = []
        self._index = GeoGridIndex(cell_deg=0.5)
        self._overpass = overpass_url

    # -- offline registry --------------------------------------------------
    def register(self, facility: Facility) -> None:
        self._registry.append(facility)
        if facility.coordinate is not None:
            self._index.add(facility.name, facility.coordinate, facility)

    def register_many(self, facilities: Iterable[Facility]) -> int:
        n = 0
        for f in facilities:
            self.register(f)
            n += 1
        return n

    def all(self) -> List[Facility]:
        return list(self._registry)

    def by_type(self, ftype: FacilityType) -> List[Facility]:
        ft = FacilityType.coerce(ftype)
        return [f for f in self._registry if f.facility_type == ft]

    def by_country(self, country_code: str) -> List[Facility]:
        cc = (country_code or "").strip().upper()
        return [f for f in self._registry if f.country_code == cc]

    def nearest(self, coord: Coordinate, limit: int = 5,
                radius_km: float = 50.0,
                ftype: Optional[FacilityType] = None) -> List[Tuple[Facility, float]]:
        hits = self._index.within(coord, radius_km)
        if ftype is not None:
            ft = FacilityType.coerce(ftype)
            hits = [(f, d) for f, d in hits if getattr(f, "facility_type", None) == ft]
        return hits[:limit]

    def in_bbox(self, bbox: BoundingBox) -> List[Facility]:
        return [f for f in self._registry if f.coordinate
                and bbox.contains(f.coordinate.latitude, f.coordinate.longitude)]

    def to_observation(self, facility: Facility) -> GeoObservation:
        lt = _FACILITY_LT.get(facility.facility_type, LocationType.FACILITY)
        ev = Evidence(source=facility.source or "osm",
                      claim=f"{facility.facility_type.value} '{facility.name}' "
                            f"in {facility.city or facility.country_code}",
                      confidence=0.6, source_url=facility.source_url,
                      precision="public listing", limitations=_OSM_LIMITATION)
        return GeoObservation(
            entity_id=facility.name, location_type=lt,
            coordinate=facility.coordinate, source=facility.source or "osm",
            source_url=facility.source_url, city=facility.city,
            country_code=facility.country_code, evidence=[ev],
            metadata={"facility_type": facility.facility_type.value,
                      "operator": facility.operator})

    # -- online (OSM Overpass) --------------------------------------------
    def build_overpass_query(self, ftype: FacilityType, bbox: BoundingBox,
                             timeout: int = 25) -> Optional[str]:
        filters = _OSM_TAGS.get(FacilityType.coerce(ftype))
        if not filters:
            return None
        bb = f"{bbox.south},{bbox.west},{bbox.north},{bbox.east}"
        parts = []
        for f in filters:
            for elem in ("node", "way", "relation"):
                parts.append(f"  {elem}{f}({bb});")
        body = "\n".join(parts)
        return f"[out:json][timeout:{timeout}];\n(\n{body}\n);\nout center tags;"

    def parse_overpass(self, payload: Dict[str, Any],
                       ftype: FacilityType) -> List[Facility]:
        out: List[Facility] = []
        ft = FacilityType.coerce(ftype)
        for el in (payload.get("elements", []) if isinstance(payload, dict) else []):
            tags = el.get("tags", {}) or {}
            lat = el.get("lat") or (el.get("center") or {}).get("lat")
            lon = el.get("lon") or (el.get("center") or {}).get("lon")
            coord = None
            if lat is not None and lon is not None:
                try:
                    coord = Coordinate(float(lat), float(lon), precision=5, source="osm")
                except Exception:
                    coord = None
            name = tags.get("name") or tags.get("official_name") or f"{ft.value}:{el.get('id')}"
            out.append(Facility(
                name=name, facility_type=ft, coordinate=coord,
                operator=tags.get("operator", ""),
                city=tags.get("addr:city", ""),
                country_code=tags.get("addr:country", ""),
                website=tags.get("website", tags.get("contact:website", "")),
                source="openstreetmap",
                source_url=f"https://www.openstreetmap.org/{el.get('type')}/{el.get('id')}",
                metadata={"osm_tags": tags}))
        return out

    async def query_osm(self, ftype: FacilityType, bbox: BoundingBox,
                        client: Any = None, register: bool = True) -> List[Facility]:
        if client is None:
            return []
        query = self.build_overpass_query(ftype, bbox)
        if not query:
            return []
        try:
            res = await client.request("POST", self._overpass,
                                       headers={"Content-Type": "text/plain"})
            # Overpass takes the query as the POST body; the shared client sends it
            # via params when a body is unsupported, so fall back to GET with data.
            if not res.ok:
                res = await client.get(self._overpass, params={"data": query})
            if not res.ok:
                return []
            facilities = self.parse_overpass(res.json(), ftype)
        except Exception as exc:
            logger.debug("overpass query failed: %s", exc)
            return []
        if register:
            self.register_many(facilities)
        return facilities


_FACILITY_LT = {
    FacilityType.GOVERNMENT: LocationType.GOVERNMENT,
    FacilityType.HOSPITAL: LocationType.HOSPITAL,
    FacilityType.UNIVERSITY: LocationType.UNIVERSITY,
    FacilityType.POWER_STATION: LocationType.POWER_STATION,
    FacilityType.TELECOM_EXCHANGE: LocationType.TELECOM,
    FacilityType.DATACENTER: LocationType.DATACENTER,
    FacilityType.IXP: LocationType.IXP,
}
