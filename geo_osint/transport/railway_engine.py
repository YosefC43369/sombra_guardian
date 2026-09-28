"""
geo_osint.transport.railway_engine — public railway network mapping (spec §8).

Maps public rail infrastructure — heavy rail, subway/metro, light rail and tram —
from OpenStreetMap ways within a bounding box, returning GeoJSON. Thin wrapper over
:class:`~geo_osint.transport.osm_ways.OSMWayQuery`.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models.geofence import BoundingBox
from .osm_ways import OSMWayQuery

_RAIL = ['["railway"="rail"]']
_METRO = ['["railway"="subway"]', '["railway"="light_rail"]', '["railway"="tram"]']


class RailwayEngine:
    def __init__(self, osm: Any = None) -> None:
        self._osm = osm or OSMWayQuery()

    async def railways(self, bbox: BoundingBox, client: Any = None) -> Dict[str, Any]:
        return await self._osm.fetch(_RAIL, bbox, "railway", client=client)

    async def metro(self, bbox: BoundingBox, client: Any = None) -> Dict[str, Any]:
        return await self._osm.fetch(_METRO, bbox, "metro", client=client)

    def build_query(self, bbox: BoundingBox) -> str:
        return self._osm.build_query(_RAIL + _METRO, bbox)
