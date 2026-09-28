"""
geo_osint.maps.administrative_boundaries — admin boundary resolution (spec §16).

Answers "what is the boundary of this country/region?" and "which country/region
contains this point?" It prefers offline Natural Earth polygons when a layer is
loaded, falls back to the gazetteer country centroid (as a labelled approximation,
not a polygon), and can use Nominatim's ``polygon_geojson`` for finer admin
boundaries when a client is supplied. Returns :class:`Geofence` objects the
visualization layer renders directly.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..data import countries as _countries
from ..models.coordinate import Coordinate
from ..models.geofence import BoundingBox, Geofence
from .naturalearth import NaturalEarthLayer

logger = logging.getLogger("modbot.geo_osint.adminbounds")


class AdministrativeBoundaryEngine:
    def __init__(self, natural_earth: Optional[NaturalEarthLayer] = None,
                 client: Any = None) -> None:
        self._ne = natural_earth or NaturalEarthLayer()
        self._client = client

    def country_boundary(self, iso: str) -> Optional[Geofence]:
        if self._ne.available:
            gf = self._ne.country_geofence(iso)
            if gf is not None:
                return gf
        # Fallback: a coarse bbox around the country centroid (clearly labelled).
        country = _countries.by_iso2(iso) or _countries.by_iso3(iso)
        if country and country.centroid:
            bbox = BoundingBox.around(country.centroid.latitude,
                                      country.centroid.longitude, 300.0)
            return Geofence(name=country.name, bbox=bbox, kind="country_approx",
                            source="gazetteer-centroid",
                            metadata={"iso": country.iso2,
                                      "note": "approximate bbox around capital, "
                                              "not a true boundary"})
        return None

    def country_of_point(self, lat: float, lon: float) -> Optional[str]:
        if self._ne.available:
            hit = self._ne.country_of(lat, lon)
            if hit:
                return hit
        return None

    async def boundary(self, query: str) -> Optional[Geofence]:
        """Fetch an admin boundary polygon via Nominatim (online, optional)."""
        if self._client is None:
            hit = _countries.resolve(query)
            return self.country_boundary(hit.iso2) if hit else None
        try:
            res = await self._client.get_json(
                "https://nominatim.openstreetmap.org/search",
                params={"q": query, "format": "jsonv2", "limit": 1,
                        "polygon_geojson": 1},
                headers={"User-Agent": "SombraGuardian-GeoOSINT/1.0"})
            if not res.ok:
                return None
            body = res.json()
        except Exception as exc:
            logger.debug("nominatim boundary failed: %s", exc)
            return None
        if not body:
            return None
        item = body[0]
        geom = item.get("geojson", {})
        rings = _rings_of(geom)
        if not rings:
            return None
        pts = [(p[1], p[0]) for ring in rings for p in ring]
        return Geofence(name=item.get("display_name", query),
                        bbox=BoundingBox.from_points(pts),
                        ring=max(rings, key=len), kind="admin",
                        source="nominatim")


def _rings_of(geom: Dict[str, Any]) -> List[List[List[float]]]:
    t = geom.get("type")
    c = geom.get("coordinates")
    if t == "Polygon" and c:
        return [c[0]]
    if t == "MultiPolygon" and c:
        return [poly[0] for poly in c if poly]
    return []
