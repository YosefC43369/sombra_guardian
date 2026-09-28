"""
geo_osint.visualization.geojson_builder — everything geographic -> GeoJSON (spec §23).

RFC 7946 GeoJSON is the engine's lingua franca for geographic output. This builder
turns any mix of the model types (coordinates, observations, resolved locations,
airports, cities, facilities, cables, routes, geofences) into valid Features and
FeatureCollections, supports all required geometry types (Point, LineString,
Polygon, MultiPolygon, FeatureCollection), and streams large collections without
holding the whole document in memory.

Pure stdlib; the output validates against the GeoJSON spec (longitude-first axis
order, right-hand rule not enforced but rings are closed).
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Iterator, List, Optional

from ..models.coordinate import Coordinate

_HAS_FEATURE = ("to_geojson_feature",)


class GeoJSONBuilder:
    def feature(self, geometry: Dict[str, Any],
                properties: Optional[Dict[str, Any]] = None,
                feature_id: Optional[str] = None) -> Dict[str, Any]:
        feat: Dict[str, Any] = {"type": "Feature", "geometry": geometry,
                                "properties": properties or {}}
        if feature_id is not None:
            feat["id"] = feature_id
        return feat

    def point(self, coord: Coordinate, properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self.feature(coord.to_geojson(), properties)

    def line_string(self, coords: List[Coordinate],
                    properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        geom = {"type": "LineString",
                "coordinates": [[c.longitude, c.latitude] for c in coords]}
        return self.feature(geom, properties)

    def polygon(self, ring: List[List[float]],
                properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        closed = list(ring)
        if closed and closed[0] != closed[-1]:
            closed.append(closed[0])
        return self.feature({"type": "Polygon", "coordinates": [closed]}, properties)

    def multi_polygon(self, polygons: List[List[List[float]]],
                      properties: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        rings = []
        for ring in polygons:
            r = list(ring)
            if r and r[0] != r[-1]:
                r.append(r[0])
            rings.append([r])
        return self.feature({"type": "MultiPolygon", "coordinates": rings}, properties)

    # -- collections -------------------------------------------------------
    def collection(self, items: Iterable[Any]) -> Dict[str, Any]:
        """Build a FeatureCollection from a mix of model objects / features."""
        return {"type": "FeatureCollection",
                "features": list(self._iter_features(items))}

    def _iter_features(self, items: Iterable[Any]) -> Iterator[Dict[str, Any]]:
        for item in items:
            if item is None:
                continue
            if isinstance(item, dict) and item.get("type") == "Feature":
                yield item
                continue
            if isinstance(item, Coordinate):
                yield self.point(item)
                continue
            fn = getattr(item, "to_geojson_feature", None)
            if callable(fn):
                feat = fn()
                if feat is not None:
                    yield feat

    def stream_collection(self, items: Iterable[Any]) -> Iterator[str]:
        """Yield a FeatureCollection as JSON text fragments (for huge datasets)."""
        yield '{"type": "FeatureCollection", "features": ['
        first = True
        for feat in self._iter_features(items):
            yield ("" if first else ",") + json.dumps(feat, ensure_ascii=False)
            first = False
        yield "]}"

    def dumps(self, items: Iterable[Any], *, indent: Optional[int] = None) -> str:
        return json.dumps(self.collection(items), ensure_ascii=False, indent=indent)

    @staticmethod
    def is_valid(fc: Dict[str, Any]) -> bool:
        """Minimal structural validation of a FeatureCollection."""
        if fc.get("type") != "FeatureCollection":
            return False
        feats = fc.get("features")
        if not isinstance(feats, list):
            return False
        for f in feats:
            if f.get("type") != "Feature" or "geometry" not in f:
                return False
            g = f["geometry"]
            if not isinstance(g, dict) or "type" not in g or "coordinates" not in g:
                return False
        return True
