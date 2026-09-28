"""
geo_osint.satellite.stac_base — shared SpatioTemporal Asset Catalog (STAC) client.

Sentinel and Landsat public archives expose a standard STAC API. This base builds
a bounded STAC ``/search`` POST body (bbox + datetime + collection + cloud filter)
and parses the returned ``FeatureCollection`` of Items into
:class:`~geo_osint.satellite.imagery_metadata.SceneMetadata` — metadata only. The
Item parser is a pure function tested offline; the network call degrades to an
empty list.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..models.geofence import BoundingBox
from .imagery_metadata import SceneMetadata, bbox_from_list

logger = logging.getLogger("modbot.geo_osint.stac")


class STACClient:
    def __init__(self, endpoint: str, source: str, client: Any = None) -> None:
        self._endpoint = endpoint
        self._source = source
        self._client = client

    def build_search_body(self, bbox: BoundingBox, *, collections: List[str],
                          datetime_range: str = "", limit: int = 20,
                          max_cloud: Optional[float] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "collections": collections,
            "bbox": [bbox.west, bbox.south, bbox.east, bbox.north],
            "limit": limit}
        if datetime_range:
            body["datetime"] = datetime_range
        if max_cloud is not None:
            body["query"] = {"eo:cloud_cover": {"lte": max_cloud}}
        return body

    def parse_item(self, item: Dict[str, Any]) -> Optional[SceneMetadata]:
        if not isinstance(item, dict):
            return None
        props = item.get("properties", {}) or {}
        assets = item.get("assets", {}) or {}
        browse = ""
        for key in ("thumbnail", "browse", "visual", "rendered_preview"):
            if key in assets and isinstance(assets[key], dict):
                browse = assets[key].get("href", "")
                break
        gsd = props.get("gsd")
        return SceneMetadata(
            scene_id=str(item.get("id", "")),
            platform=str(props.get("platform", props.get("constellation", ""))),
            sensor=str(props.get("instruments", props.get("instrument", "")) or ""),
            datetime=str(props.get("datetime", props.get("start_datetime", ""))),
            cloud_cover=_float(props.get("eo:cloud_cover")),
            resolution_m=_float(gsd),
            bbox=bbox_from_list(item.get("bbox")),
            collection=str(item.get("collection", "")),
            browse_url=browse, source=self._source,
            metadata={"stac_id": item.get("id")})

    def parse_search(self, payload: Dict[str, Any]) -> List[SceneMetadata]:
        feats = payload.get("features", []) if isinstance(payload, dict) else []
        out = [self.parse_item(f) for f in feats]
        return [s for s in out if s is not None]

    async def search(self, bbox: BoundingBox, *, collections: List[str],
                     datetime_range: str = "", limit: int = 20,
                     max_cloud: Optional[float] = None) -> List[SceneMetadata]:
        if self._client is None:
            return []
        body = self.build_search_body(bbox, collections=collections,
                                      datetime_range=datetime_range, limit=limit,
                                      max_cloud=max_cloud)
        try:
            res = await self._client.request(
                "POST", f"{self._endpoint}/search",
                headers={"Content-Type": "application/json"})
            if not res.ok:
                # Some STAC servers accept GET with querystring; try a GET fallback.
                res = await self._client.get(f"{self._endpoint}/search",
                                             params={"collections": ",".join(collections),
                                                     "bbox": ",".join(map(str, body["bbox"])),
                                                     "limit": limit})
            if not res.ok:
                return []
            return self.parse_search(res.json())
        except Exception as exc:
            logger.debug("STAC search failed: %s", exc)
            return []


def _float(v: Any) -> Optional[float]:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None
