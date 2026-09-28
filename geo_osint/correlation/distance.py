"""
geo_osint.correlation.distance — the distance engine (spec §25).

Thin, typed wrappers over the coordinate core's Haversine and Vincenty-geodesic
functions, plus the domain conveniences the spec calls for: city-to-city,
airport-to-airport, coordinate-to-coordinate, facility-to-facility, and a full
pairwise distance matrix. Everything here is pure and offline.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models.airport import Airport
from ..models.city import City
from ..models.coordinate import Coordinate, geodesic_km, haversine_km
from ..models.infrastructure import Facility

_HasCoord = Any  # anything exposing a .coordinate: Optional[Coordinate]


class DistanceEngine:
    def __init__(self, method: str = "geodesic") -> None:
        if method not in ("geodesic", "haversine"):
            raise ValueError("method must be 'geodesic' or 'haversine'")
        self.method = method

    def between(self, a: Coordinate, b: Coordinate) -> float:
        return round(a.distance_km(b, method=self.method), 3)

    def coordinate_to_coordinate(self, a: Coordinate, b: Coordinate) -> float:
        return self.between(a, b)

    def city_to_city(self, a: City, b: City) -> Optional[float]:
        return self._obj(a, b)

    def airport_to_airport(self, a: Airport, b: Airport) -> Optional[float]:
        return self._obj(a, b)

    def facility_to_facility(self, a: Facility, b: Facility) -> Optional[float]:
        return self._obj(a, b)

    def nearest_of(self, origin: Coordinate,
                   candidates: Sequence[_HasCoord]) -> Optional[Tuple[_HasCoord, float]]:
        best = None
        best_d = float("inf")
        for c in candidates:
            coord = getattr(c, "coordinate", None)
            if coord is None:
                continue
            d = origin.distance_km(coord, method=self.method)
            if d < best_d:
                best_d, best = d, c
        return (best, round(best_d, 3)) if best is not None else None

    def matrix(self, points: Sequence[Coordinate]) -> List[List[float]]:
        """Symmetric pairwise distance matrix (km)."""
        n = len(points)
        m = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                d = self.between(points[i], points[j])
                m[i][j] = m[j][i] = d
        return m

    def total_path_km(self, points: Sequence[Coordinate]) -> float:
        return round(sum(self.between(points[i], points[i + 1])
                         for i in range(len(points) - 1)), 3)

    def _obj(self, a: _HasCoord, b: _HasCoord) -> Optional[float]:
        ca, cb = getattr(a, "coordinate", None), getattr(b, "coordinate", None)
        return self.between(ca, cb) if ca and cb else None
