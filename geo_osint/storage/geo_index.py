"""
geo_osint.storage.geo_index — an in-memory spatial index for fast queries (spec §51).

A uniform grid ("R-tree-lite") over WGS84: items are bucketed by integer
``(lat//cell, lon//cell)`` cells, so a radius or nearest-k query only scans the
handful of cells overlapping the query circle instead of the whole dataset. This
turns proximity/nearest from O(n) into roughly O(k) for the millions-of-records
target, with zero third-party dependencies. Cell size is chosen from the typical
query radius. The index stores ``(id, coordinate, payload)`` triples and never
mutates the payloads.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from ..models.coordinate import Coordinate, haversine_km


class GeoGridIndex:
    def __init__(self, cell_deg: float = 1.0) -> None:
        if cell_deg <= 0:
            raise ValueError("cell_deg must be positive")
        self._cell = cell_deg
        self._grid: Dict[Tuple[int, int], List[Tuple[str, Coordinate, Any]]] = defaultdict(list)
        self._count = 0

    def __len__(self) -> int:
        return self._count

    def _cell_of(self, lat: float, lon: float) -> Tuple[int, int]:
        return (int(math.floor(lat / self._cell)), int(math.floor(lon / self._cell)))

    # -- mutation ----------------------------------------------------------
    def add(self, item_id: str, coord: Coordinate, payload: Any = None) -> None:
        self._grid[self._cell_of(coord.latitude, coord.longitude)].append(
            (item_id, coord, payload if payload is not None else item_id))
        self._count += 1

    def add_many(self, items: Iterable[Tuple[str, Coordinate, Any]]) -> int:
        n = 0
        for item_id, coord, payload in items:
            self.add(item_id, coord, payload)
            n += 1
        return n

    def index_objects(self, objects: Iterable[Any],
                      id_attr: str = "geo_id") -> int:
        """Index any objects exposing ``.coordinate`` (observations, facilities…)."""
        n = 0
        for obj in objects:
            coord = getattr(obj, "coordinate", None)
            if coord is None:
                continue
            item_id = str(getattr(obj, id_attr, None)
                          or getattr(obj, "name", None) or id(obj))
            self.add(item_id, coord, obj)
            n += 1
        return n

    # -- queries -----------------------------------------------------------
    def _candidate_cells(self, lat: float, lon: float,
                         radius_km: float) -> Iterator[Tuple[int, int]]:
        dlat = radius_km / 111.32
        dlon = radius_km / (111.32 * max(0.01, math.cos(math.radians(lat))))
        lat_span = int(math.ceil(dlat / self._cell)) + 1
        lon_span = int(math.ceil(dlon / self._cell)) + 1
        clat, clon = self._cell_of(lat, lon)
        for dy in range(-lat_span, lat_span + 1):
            for dx in range(-lon_span, lon_span + 1):
                yield (clat + dy, clon + dx)

    def within(self, coord: Coordinate, radius_km: float) -> List[Tuple[Any, float]]:
        """All indexed items within ``radius_km`` of ``coord``, nearest-first."""
        out: List[Tuple[Any, float]] = []
        for cell in self._candidate_cells(coord.latitude, coord.longitude, radius_km):
            for _id, c, payload in self._grid.get(cell, ()):  # type: ignore[arg-type]
                d = haversine_km(coord.latitude, coord.longitude,
                                 c.latitude, c.longitude)
                if d <= radius_km:
                    out.append((payload, round(d, 3)))
        out.sort(key=lambda t: t[1])
        return out

    def nearest(self, coord: Coordinate, k: int = 1,
                max_radius_km: float = 20000.0) -> List[Tuple[Any, float]]:
        """The ``k`` nearest indexed items, expanding the search ring as needed."""
        radius = self._cell * 111.32
        seen: List[Tuple[Any, float]] = []
        while radius <= max_radius_km:
            seen = self.within(coord, radius)
            if len(seen) >= k:
                break
            radius *= 2
        return seen[:k]

    def stats(self) -> Dict[str, Any]:
        cells = len(self._grid)
        return {"items": self._count, "cells": cells, "cell_deg": self._cell,
                "avg_per_cell": round(self._count / cells, 2) if cells else 0}
