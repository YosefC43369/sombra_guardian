"""
geo_osint.transport.public_transit_engine — public transit lines & hubs (spec §8).

Maps public-transit infrastructure — bus/train/subway/tram *routes* and transit
hubs (stations, interchanges) — from public OpenStreetMap route relations and
station nodes within a bounding box, returning GeoJSON. Public schedule/route data
only; no live vehicle tracking.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models.geofence import BoundingBox
from .osm_ways import OSMWayQuery

_TRANSIT_WAYS = ['["route"="bus"]', '["route"="train"]', '["route"="subway"]',
                 '["route"="tram"]']


class PublicTransitEngine:
    def __init__(self, osm: Any = None) -> None:
        self._osm = osm or OSMWayQuery()

    async def routes(self, bbox: BoundingBox, client: Any = None) -> Dict[str, Any]:
        return await self._osm.fetch(_TRANSIT_WAYS, bbox, "transit_route", client=client)

    def build_query(self, bbox: BoundingBox) -> str:
        return self._osm.build_query(_TRANSIT_WAYS, bbox)
