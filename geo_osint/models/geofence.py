"""
geo_osint.models.geofence — bounding boxes and polygons over public areas.

IMPORTANT SCOPE NOTE (spec §50): geofencing here operates over *public
geographic areas* — a country's bounding box, an airport's boundary polygon, a
city extent, a satellite scene footprint. It is used for spatial queries
("which observations fall inside this administrative polygon", "does this scene
cover this port") and for GeoJSON export. It is **never** used to fence
individuals or to alert on a person entering/leaving an area. The engine has no
device-location input to fence against, by construction.

Geometry is pure stdlib: a bounding box and a ray-casting point-in-polygon test,
both dependency-free.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .coordinate import Coordinate, haversine_km


@dataclass(frozen=True)
class BoundingBox:
    """An axis-aligned WGS84 bounding box (west/south/east/north)."""

    west: float
    south: float
    east: float
    north: float

    def __post_init__(self) -> None:
        if self.south > self.north:
            raise ValueError(f"south {self.south} > north {self.north}")

    @property
    def crosses_antimeridian(self) -> bool:
        return self.west > self.east

    def contains(self, lat: float, lon: float) -> bool:
        if not (self.south <= lat <= self.north):
            return False
        if self.crosses_antimeridian:
            return lon >= self.west or lon <= self.east
        return self.west <= lon <= self.east

    def center(self) -> Coordinate:
        lat = (self.south + self.north) / 2.0
        if self.crosses_antimeridian:
            lon = (self.west + self.east + 360.0) / 2.0
            if lon > 180.0:
                lon -= 360.0
        else:
            lon = (self.west + self.east) / 2.0
        return Coordinate(lat, lon, source="bbox-center")

    def diagonal_km(self) -> float:
        return haversine_km(self.south, self.west, self.north, self.east)

    def expanded(self, km: float) -> "BoundingBox":
        """Grow the box by roughly ``km`` on every side (for radius queries)."""
        dlat = km / 111.32
        mid_lat = (self.south + self.north) / 2.0
        dlon = km / (111.32 * max(0.01, math.cos(math.radians(mid_lat))))
        return BoundingBox(self.west - dlon, max(-90.0, self.south - dlat),
                           self.east + dlon, min(90.0, self.north + dlat))

    def to_polygon(self) -> List[List[float]]:
        """A closed GeoJSON-order ring [lon, lat] for the box."""
        return [[self.west, self.south], [self.east, self.south],
                [self.east, self.north], [self.west, self.north],
                [self.west, self.south]]

    def to_geojson(self) -> Dict[str, Any]:
        return {"type": "Polygon", "coordinates": [self.to_polygon()]}

    def to_dict(self) -> Dict[str, Any]:
        return {"west": self.west, "south": self.south,
                "east": self.east, "north": self.north}

    @classmethod
    def from_points(cls, points: Sequence[Tuple[float, float]]) -> "BoundingBox":
        """Bounding box of (lat, lon) points."""
        if not points:
            raise ValueError("no points")
        lats = [p[0] for p in points]
        lons = [p[1] for p in points]
        return cls(min(lons), min(lats), max(lons), max(lats))

    @classmethod
    def around(cls, lat: float, lon: float, radius_km: float) -> "BoundingBox":
        dlat = radius_km / 111.32
        dlon = radius_km / (111.32 * max(0.01, math.cos(math.radians(lat))))
        return cls(lon - dlon, max(-90.0, lat - dlat),
                   lon + dlon, min(90.0, lat + dlat))


@dataclass
class Geofence:
    """A named area: a bounding box and, optionally, a polygon ring.

    Rings use GeoJSON ``[lon, lat]`` order. Point-in-polygon uses the standard
    even-odd ray-casting rule; the bounding box is a fast pre-filter.
    """

    name: str
    bbox: BoundingBox
    ring: List[List[float]] = field(default_factory=list)   # [[lon, lat], ...]
    kind: str = "area"
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def contains(self, lat: float, lon: float) -> bool:
        if not self.bbox.contains(lat, lon):
            return False
        if not self.ring or len(self.ring) < 4:
            return True                     # box-only fence
        return _point_in_ring(lon, lat, self.ring)

    def contains_coordinate(self, coord: Coordinate) -> bool:
        return self.contains(coord.latitude, coord.longitude)

    def to_geojson_feature(self) -> Dict[str, Any]:
        geometry: Dict[str, Any]
        if self.ring and len(self.ring) >= 4:
            geometry = {"type": "Polygon", "coordinates": [self.ring]}
        else:
            geometry = self.bbox.to_geojson()
        return {"type": "Feature", "geometry": geometry,
                "properties": {"name": self.name, "kind": self.kind,
                               "source": self.source, **self.metadata}}

    @classmethod
    def from_ring(cls, name: str, ring: List[List[float]], **kw) -> "Geofence":
        pts = [(p[1], p[0]) for p in ring]
        return cls(name=name, bbox=BoundingBox.from_points(pts), ring=ring, **kw)


def _point_in_ring(x: float, y: float, ring: List[List[float]]) -> bool:
    """Even-odd ray casting; ``ring`` is [[lon, lat], ...] (x=lon, y=lat)."""
    inside = False
    n = len(ring)
    j = n - 1
    for i in range(n):
        xi, yi = ring[i][0], ring[i][1]
        xj, yj = ring[j][0], ring[j][1]
        if ((yi > y) != (yj > y)) and \
                (x < (xj - xi) * (y - yi) / ((yj - yi) or 1e-12) + xi):
            inside = not inside
        j = i
    return inside
