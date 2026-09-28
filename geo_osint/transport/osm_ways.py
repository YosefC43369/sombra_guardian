"""
geo_osint.transport.osm_ways — shared OSM Overpass helper for linear transport
infrastructure (roads, railways, transit routes).

Roads, railways and public-transit lines are public OpenStreetMap ways. This helper
builds a bounded, read-only Overpass query for a set of way tags and parses the
returned geometry into GeoJSON LineString features. The road/railway/transit engines
are thin category wrappers over it. Offline (no client) they return empty; nothing
is scraped in bulk — a single bounded query of already-public map data per call
(spec §8, §17).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..models.geofence import BoundingBox

logger = logging.getLogger("modbot.geo_osint.osm_ways")

_OVERPASS_URL = "https://overpass-api.de/api/interpreter"


class OSMWayQuery:
    def __init__(self, overpass_url: str = _OVERPASS_URL) -> None:
        self._url = overpass_url

    def build_query(self, tag_filters: List[str], bbox: BoundingBox,
                    timeout: int = 25) -> str:
        bb = f"{bbox.south},{bbox.west},{bbox.north},{bbox.east}"
        parts = [f"  way{f}({bb});" for f in tag_filters]
        return (f"[out:json][timeout:{timeout}];\n(\n"
                + "\n".join(parts) + "\n);\nout geom;")

    def parse_ways(self, payload: Dict[str, Any], kind: str) -> Dict[str, Any]:
        feats = []
        for el in (payload.get("elements", []) if isinstance(payload, dict) else []):
            if el.get("type") != "way":
                continue
            geometry = el.get("geometry")
            if not isinstance(geometry, list) or len(geometry) < 2:
                continue
            coords = [[pt["lon"], pt["lat"]] for pt in geometry
                      if "lon" in pt and "lat" in pt]
            if len(coords) < 2:
                continue
            tags = el.get("tags", {}) or {}
            feats.append({
                "type": "Feature",
                "geometry": {"type": "LineString", "coordinates": coords},
                "properties": {"kind": kind, "name": tags.get("name", ""),
                               "ref": tags.get("ref", ""),
                               "osm_id": el.get("id"), "tags": tags}})
        return {"type": "FeatureCollection", "features": feats}

    async def fetch(self, tag_filters: List[str], bbox: BoundingBox,
                    kind: str, client: Any = None) -> Dict[str, Any]:
        if client is None:
            return {"type": "FeatureCollection", "features": []}
        query = self.build_query(tag_filters, bbox)
        try:
            res = await client.get(self._url, params={"data": query})
            if not res.ok:
                return {"type": "FeatureCollection", "features": []}
            return self.parse_ways(res.json(), kind)
        except Exception as exc:
            logger.debug("overpass way fetch failed: %s", exc)
            return {"type": "FeatureCollection", "features": []}
