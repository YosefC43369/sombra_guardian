"""
geo_osint.infrastructure.telecom_engine — public telecom infrastructure (spec §38).

Collects public telecom metadata only — telephone/telecom exchanges and public
data-centre map tags from OpenStreetMap, or an injected public dataset. It is a
category wrapper over :class:`FacilityEngine`. Explicitly: NO private
infrastructure discovery, no active probing, no attempt to enumerate a carrier's
non-public estate (spec §38). Only already-public map data is read.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from ..models.coordinate import Coordinate
from ..models.geofence import BoundingBox
from ..models.infrastructure import Facility, FacilityType
from .facility_engine import FacilityEngine


class TelecomInfrastructureEngine:
    CATEGORY = FacilityType.TELECOM_EXCHANGE

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
