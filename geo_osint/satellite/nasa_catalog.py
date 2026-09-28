"""
geo_osint.satellite.nasa_catalog — NASA EarthData CMR granule metadata (spec §21-22).

Queries NASA's public Common Metadata Repository (CMR) granule search for scene
*metadata* (temporal + spatial coverage) over a bounding box — no imagery download.
Also supports building a historical *availability timeline* (spec §22): the count
and date span of public acquisitions over an area, returned as metadata only. The
granule parser is a pure function tested offline.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..models.geofence import BoundingBox
from .imagery_metadata import SceneMetadata, bbox_from_list

logger = logging.getLogger("modbot.geo_osint.nasa")

CMR = "https://cmr.earthdata.nasa.gov/search/granules.json"


class NASACatalog:
    def __init__(self, client: Any = None, endpoint: str = CMR) -> None:
        self._client = client
        self._endpoint = endpoint

    def parse_granules(self, payload: Dict[str, Any]) -> List[SceneMetadata]:
        entries = (((payload or {}).get("feed", {}) or {}).get("entry", [])
                   if isinstance(payload, dict) else [])
        out: List[SceneMetadata] = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            bbox = None
            boxes = e.get("boxes")
            if isinstance(boxes, list) and boxes:
                parts = str(boxes[0]).split()
                if len(parts) == 4:      # CMR order: south west north east
                    try:
                        s, w, n, ee = map(float, parts)
                        bbox = BoundingBox(w, s, ee, n)
                    except ValueError:
                        bbox = None
            out.append(SceneMetadata(
                scene_id=str(e.get("id", e.get("title", ""))),
                platform=str(e.get("platform", "")),
                datetime=str(e.get("time_start", "")),
                bbox=bbox, collection=str(e.get("collection_concept_id", "")),
                browse_url=_browse(e), source="nasa-cmr",
                metadata={"time_end": e.get("time_end", ""),
                          "dataset_id": e.get("dataset_id", "")}))
        return out

    async def search(self, bbox: BoundingBox, *, temporal: str = "",
                     limit: int = 20) -> List[SceneMetadata]:
        if self._client is None:
            return []
        params = {"bounding_box": f"{bbox.west},{bbox.south},{bbox.east},{bbox.north}",
                  "page_size": limit, "sort_key": "-start_date"}
        if temporal:
            params["temporal"] = temporal
        try:
            res = await self._client.get_json(self._endpoint, params=params)
            if not res.ok:
                return []
            return self.parse_granules(res.json())
        except Exception as exc:
            logger.debug("CMR search failed: %s", exc)
            return []

    def availability_timeline(self, scenes: List[SceneMetadata]) -> Dict[str, Any]:
        """Historical availability metadata (spec §22): count + span, no imagery."""
        dates = sorted(s.datetime for s in scenes if s.datetime)
        return {"scene_count": len(scenes),
                "earliest": dates[0] if dates else None,
                "latest": dates[-1] if dates else None,
                "platforms": sorted({s.platform for s in scenes if s.platform})}


def _browse(entry: Dict[str, Any]) -> str:
    for link in entry.get("links", []) or []:
        if isinstance(link, dict) and "browse" in str(link.get("rel", "")):
            return link.get("href", "")
    return ""
