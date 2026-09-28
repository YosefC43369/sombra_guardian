"""
geo_osint.visualization.cluster_builder — render clustering output as GeoJSON.

Turns a :class:`~geo_osint.correlation.cluster.ClusterResult` into map layers: a
Point per cluster centroid (sized by member count), the member points tagged with
their cluster label, an optional convex-hull Polygon per cluster, and the noise
points. Pure stdlib (a Graham-scan convex hull, no shapely dependency).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models.coordinate import Coordinate
from .geojson_builder import GeoJSONBuilder


class ClusterMapBuilder:
    def __init__(self) -> None:
        self._geojson = GeoJSONBuilder()

    def centroids(self, cluster_result: Any) -> Dict[str, Any]:
        feats = []
        for c in cluster_result.clusters:
            if c.centroid is None:
                continue
            feats.append(self._geojson.point(c.centroid,
                {"label": c.label, "size": c.size, "role": "centroid"}))
        return {"type": "FeatureCollection", "features": feats}

    def members(self, cluster_result: Any,
                accessor=lambda x: getattr(x, "coordinate", None)) -> Dict[str, Any]:
        feats = []
        for c in cluster_result.clusters:
            for m in c.members:
                coord = accessor(m) if not isinstance(m, Coordinate) else m
                if coord is None:
                    continue
                feats.append(self._geojson.point(coord,
                    {"label": c.label, "name": _name(m), "role": "member"}))
        return {"type": "FeatureCollection", "features": feats}

    def hulls(self, cluster_result: Any,
              accessor=lambda x: getattr(x, "coordinate", None)) -> Dict[str, Any]:
        feats = []
        for c in cluster_result.clusters:
            pts = []
            for m in c.members:
                coord = accessor(m) if not isinstance(m, Coordinate) else m
                if coord is not None:
                    pts.append([coord.longitude, coord.latitude])
            hull = _convex_hull(pts)
            if len(hull) >= 3:
                feats.append(self._geojson.polygon(hull,
                    {"label": c.label, "size": c.size, "role": "hull"}))
        return {"type": "FeatureCollection", "features": feats}

    def noise(self, cluster_result: Any,
              accessor=lambda x: getattr(x, "coordinate", None)) -> Dict[str, Any]:
        feats = []
        for m in cluster_result.noise:
            coord = accessor(m) if not isinstance(m, Coordinate) else m
            if coord is not None:
                feats.append(self._geojson.point(coord, {"role": "noise", "name": _name(m)}))
        return {"type": "FeatureCollection", "features": feats}


def _name(item: Any) -> str:
    for a in ("name", "display_name", "entity_id", "code"):
        v = getattr(item, a, None)
        if v:
            return str(v)
    return ""


def _convex_hull(points: List[List[float]]) -> List[List[float]]:
    """Andrew's monotone chain convex hull. Returns a closed ring [lon,lat]."""
    pts = sorted(set((p[0], p[1]) for p in points))
    if len(pts) <= 2:
        return [list(p) for p in pts]

    def cross(o, a, b):
        return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])

    lower: List = []
    for p in pts:
        while len(lower) >= 2 and cross(lower[-2], lower[-1], p) <= 0:
            lower.pop()
        lower.append(p)
    upper: List = []
    for p in reversed(pts):
        while len(upper) >= 2 and cross(upper[-2], upper[-1], p) <= 0:
            upper.pop()
        upper.append(p)
    ring = lower[:-1] + upper[:-1]
    ring.append(ring[0])
    return [list(p) for p in ring]
