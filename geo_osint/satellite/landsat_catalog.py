"""
geo_osint.satellite.landsat_catalog — Landsat scene metadata (spec §21).

Queries the public Element84 Earth Search STAC API for Landsat Collection-2 L2 scene
*metadata* over a bounding box and time range. Metadata only; no imagery download.
Thin wrapper over :class:`STACClient`.
"""

from __future__ import annotations

from typing import Any, List, Optional

from ..models.geofence import BoundingBox
from .imagery_metadata import SceneMetadata
from .stac_base import STACClient

EARTH_SEARCH = "https://earth-search.aws.element84.com/v1"
COLLECTIONS = ["landsat-c2-l2"]


class LandsatCatalog:
    def __init__(self, client: Any = None, endpoint: str = EARTH_SEARCH) -> None:
        self._stac = STACClient(endpoint, "landsat", client=client)

    async def search(self, bbox: BoundingBox, *, datetime_range: str = "",
                     limit: int = 20, max_cloud: Optional[float] = None
                     ) -> List[SceneMetadata]:
        return await self._stac.search(bbox, collections=COLLECTIONS,
                                       datetime_range=datetime_range,
                                       limit=limit, max_cloud=max_cloud)

    def parse_search(self, payload) -> List[SceneMetadata]:
        return self._stac.parse_search(payload)
