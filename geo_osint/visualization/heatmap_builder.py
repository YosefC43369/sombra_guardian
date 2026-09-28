"""
geo_osint.visualization.heatmap_builder — weighted density layers (spec §24).

Builds two heatmap representations from a set of coordinates/observations:

  * a **weighted point** list ``[lat, lon, weight]`` for a client-side heatmap
    plugin (e.g. Leaflet.heat);
  * a **binned grid** aggregation (counts per lat/lon cell) exported as GeoJSON
    Polygons with an intensity property, for renderers without a heat plugin.

Weights default to observation confidence so denser, better-evidenced areas read
hotter. Pure stdlib.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models.coordinate import Coordinate


class HeatmapBuilder:
    def weighted_points(self, items: List[Any],
                        weight_fn: Optional[Callable[[Any], float]] = None
                        ) -> List[List[float]]:
        out: List[List[float]] = []
        for it in items:
            coord = it if isinstance(it, Coordinate) else getattr(it, "coordinate", None)
            if coord is None:
                continue
            w = weight_fn(it) if weight_fn else float(getattr(it, "confidence", 1.0) or 1.0)
            out.append([round(coord.latitude, 6), round(coord.longitude, 6), round(w, 4)])
        return out

    def grid(self, items: List[Any], cell_deg: float = 1.0,
             weight_fn: Optional[Callable[[Any], float]] = None) -> Dict[str, Any]:
        """Aggregate into square cells of ``cell_deg`` degrees; GeoJSON Polygons."""
        buckets: Dict[Tuple[int, int], float] = defaultdict(float)
        counts: Dict[Tuple[int, int], int] = defaultdict(int)
        for it in items:
            coord = it if isinstance(it, Coordinate) else getattr(it, "coordinate", None)
            if coord is None:
                continue
            gx = int(coord.longitude // cell_deg)
            gy = int(coord.latitude // cell_deg)
            w = weight_fn(it) if weight_fn else float(getattr(it, "confidence", 1.0) or 1.0)
            buckets[(gx, gy)] += w
            counts[(gx, gy)] += 1
        max_w = max(buckets.values()) if buckets else 1.0
        feats = []
        for (gx, gy), w in buckets.items():
            west, south = gx * cell_deg, gy * cell_deg
            east, north = west + cell_deg, south + cell_deg
            feats.append({
                "type": "Feature",
                "geometry": {"type": "Polygon", "coordinates": [[
                    [west, south], [east, south], [east, north],
                    [west, north], [west, south]]]},
                "properties": {"weight": round(w, 4), "count": counts[(gx, gy)],
                               "intensity": round(w / max_w, 4)}})
        return {"type": "FeatureCollection", "features": feats,
                "properties": {"cell_deg": cell_deg, "max_weight": round(max_w, 4)}}
