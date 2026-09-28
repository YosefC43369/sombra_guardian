"""
geo_osint.satellite.imagery_metadata — the satellite scene metadata record (spec §21).

A :class:`SceneMetadata` captures the PUBLIC metadata of a satellite acquisition —
scene id, platform/sensor, capture datetime, cloud cover, ground resolution, the
footprint bounding box and a browse/asset URL — and nothing else. The engine works
with *metadata only*: it never downloads imagery unless a caller explicitly does so
via the returned asset URL (spec §21 "do not download imagery unless requested
separately"). This is the common shape produced by the Sentinel/Landsat/NASA
catalog clients (all STAC/CMR-based), so a caller queries one interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models.geofence import BoundingBox


@dataclass
class SceneMetadata:
    scene_id: str
    platform: str = ""            # e.g. "sentinel-2a", "landsat-9"
    sensor: str = ""              # e.g. "MSI", "OLI_TIRS"
    datetime: str = ""           # ISO acquisition time
    cloud_cover: Optional[float] = None
    resolution_m: Optional[float] = None
    bbox: Optional[BoundingBox] = None
    collection: str = ""
    browse_url: str = ""
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def center(self):
        return self.bbox.center() if self.bbox else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scene_id": self.scene_id, "platform": self.platform,
            "sensor": self.sensor, "datetime": self.datetime,
            "cloud_cover": self.cloud_cover, "resolution_m": self.resolution_m,
            "bbox": self.bbox.to_dict() if self.bbox else None,
            "collection": self.collection, "browse_url": self.browse_url,
            "source": self.source, "metadata": dict(self.metadata)}

    def to_geojson_feature(self) -> Optional[Dict[str, Any]]:
        if not self.bbox:
            return None
        return {"type": "Feature", "geometry": self.bbox.to_geojson(),
                "properties": {"scene_id": self.scene_id, "platform": self.platform,
                               "datetime": self.datetime,
                               "cloud_cover": self.cloud_cover,
                               "collection": self.collection}}


def bbox_from_list(bbox: Any) -> Optional[BoundingBox]:
    """Build a BoundingBox from a STAC ``[west, south, east, north]`` list."""
    if isinstance(bbox, (list, tuple)) and len(bbox) >= 4:
        try:
            return BoundingBox(float(bbox[0]), float(bbox[1]),
                               float(bbox[2]), float(bbox[3]))
        except (TypeError, ValueError):
            return None
    return None
