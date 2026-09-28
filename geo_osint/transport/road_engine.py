"""
geo_osint.transport.road_engine — public road network mapping (spec §8).

Maps public road infrastructure — motorways, trunk roads, primary roads, bridges
and tunnels — from OpenStreetMap ways within a bounding box, returning GeoJSON. A
thin category wrapper over :class:`~geo_osint.transport.osm_ways.OSMWayQuery`.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models.geofence import BoundingBox
from .osm_ways import OSMWayQuery

_HIGHWAY = ['["highway"="motorway"]', '["highway"="trunk"]',
            '["highway"="primary"]']
_STRUCTURES = ['["bridge"="yes"]["highway"]', '["tunnel"="yes"]["highway"]']


class RoadEngine:
    def __init__(self, osm: Any = None) -> None:
        self._osm = osm or OSMWayQuery()

    async def major_roads(self, bbox: BoundingBox, client: Any = None) -> Dict[str, Any]:
        return await self._osm.fetch(_HIGHWAY, bbox, "road", client=client)

    async def structures(self, bbox: BoundingBox, client: Any = None) -> Dict[str, Any]:
        return await self._osm.fetch(_STRUCTURES, bbox, "road_structure", client=client)

    def build_query(self, bbox: BoundingBox) -> str:
        return self._osm.build_query(_HIGHWAY, bbox)
