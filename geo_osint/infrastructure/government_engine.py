"""
geo_osint.infrastructure.government_engine — publicly-listed government facilities
(spec §39).

Collects ONLY publicly-listed government buildings — ministries, town/city halls,
courthouses, embassies, public agencies — from public OpenStreetMap tags or an
injected public dataset. It is a thin category wrapper over
:class:`~geo_osint.infrastructure.facility_engine.FacilityEngine` fixing the
government tag set. Nothing non-public, sensitive or restricted is discovered or
inferred; every record is a facility a member of the public could look up.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from ..models.coordinate import Coordinate
from ..models.geofence import BoundingBox
from ..models.infrastructure import Facility, FacilityType
from .facility_engine import FacilityEngine


class GovernmentFacilityEngine:
    CATEGORY = FacilityType.GOVERNMENT

    def __init__(self, facility_engine: Optional[FacilityEngine] = None) -> None:
        self._fac = facility_engine or FacilityEngine()

    def register(self, facility: Facility) -> None:
        facility.facility_type = self.CATEGORY
        self._fac.register(facility)

    def all(self) -> List[Facility]:
        return self._fac.by_type(self.CATEGORY)

    def nearest(self, coord: Coordinate, limit: int = 5,
                radius_km: float = 50.0) -> List[Tuple[Facility, float]]:
        return self._fac.nearest(coord, limit, radius_km, ftype=self.CATEGORY)

    async def discover(self, bbox: BoundingBox, client: Any = None) -> List[Facility]:
        return await self._fac.query_osm(self.CATEGORY, bbox, client=client)
