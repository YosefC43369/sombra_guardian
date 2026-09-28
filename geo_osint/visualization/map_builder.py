"""
geo_osint.visualization.map_builder — assemble map-ready outputs (spec §24).

Produces a serialisable *map specification* (layers of markers, routes,
boundaries, clusters, heatmaps) that a front-end can render, plus a self-contained
Leaflet HTML export for a quick standalone view. The HTML uses the public Leaflet
CDN and OpenStreetMap tiles (respecting OSM's tile-usage policy — attribution
included, no bulk tile scraping); when offline, the JSON spec is still fully
usable by any GeoJSON-aware renderer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models.coordinate import Coordinate
from .geojson_builder import GeoJSONBuilder


@dataclass
class MapLayer:
    name: str
    kind: str                    # markers | route | boundary | cluster | heatmap
    feature_collection: Dict[str, Any]
    style: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "kind": self.kind,
                "style": self.style, "data": self.feature_collection}


class MapBuilder:
    def __init__(self) -> None:
        self._geojson = GeoJSONBuilder()
        self._layers: List[MapLayer] = []

    def add_markers(self, name: str, items: List[Any],
                    style: Optional[Dict[str, Any]] = None) -> "MapBuilder":
        self._layers.append(MapLayer(name, "markers",
                                     self._geojson.collection(items), style or {}))
        return self

    def add_route(self, name: str, route: Any,
                  style: Optional[Dict[str, Any]] = None) -> "MapBuilder":
        fc = {"type": "FeatureCollection", "features": [route.to_geojson_feature()]}
        self._layers.append(MapLayer(name, "route", fc,
                                     style or {"color": "#3388ff"}))
        return self

    def add_boundary(self, name: str, geofence: Any,
                     style: Optional[Dict[str, Any]] = None) -> "MapBuilder":
        fc = {"type": "FeatureCollection", "features": [geofence.to_geojson_feature()]}
        self._layers.append(MapLayer(name, "boundary", fc,
                                     style or {"color": "#ff6600", "fill": False}))
        return self

    def add_feature_collection(self, name: str, kind: str,
                               fc: Dict[str, Any],
                               style: Optional[Dict[str, Any]] = None) -> "MapBuilder":
        self._layers.append(MapLayer(name, kind, fc, style or {}))
        return self

    # -- viewport ----------------------------------------------------------
    def _all_points(self) -> List[List[float]]:
        pts: List[List[float]] = []
        for layer in self._layers:
            for feat in layer.feature_collection.get("features", []):
                self._collect_coords(feat.get("geometry", {}), pts)
        return pts

    def _collect_coords(self, geom: Dict[str, Any], out: List[List[float]]) -> None:
        t = geom.get("type")
        c = geom.get("coordinates")
        if t == "Point" and isinstance(c, list):
            out.append(c[:2])
        elif t in ("LineString", "MultiPoint"):
            out.extend(p[:2] for p in c)
        elif t in ("Polygon", "MultiLineString"):
            for ring in c:
                out.extend(p[:2] for p in ring)
        elif t == "MultiPolygon":
            for poly in c:
                for ring in poly:
                    out.extend(p[:2] for p in ring)

    def bounds(self) -> Optional[Dict[str, float]]:
        pts = self._all_points()
        if not pts:
            return None
        lons = [p[0] for p in pts]
        lats = [p[1] for p in pts]
        return {"west": min(lons), "south": min(lats),
                "east": max(lons), "north": max(lats)}

    def center(self) -> Coordinate:
        b = self.bounds()
        if not b:
            return Coordinate(0.0, 0.0, source="map-default")
        return Coordinate((b["south"] + b["north"]) / 2,
                          (b["west"] + b["east"]) / 2, source="map-center")

    # -- output ------------------------------------------------------------
    def to_spec(self, title: str = "Geo-OSINT Map") -> Dict[str, Any]:
        return {"title": title, "center": self.center().to_dict(),
                "bounds": self.bounds(),
                "layers": [l.to_dict() for l in self._layers]}

    def to_html(self, title: str = "Geo-OSINT Map") -> str:
        spec = self.to_spec(title)
        center = spec["center"]
        data = json.dumps(spec["layers"], ensure_ascii=False)
        return _LEAFLET_TEMPLATE.format(
            title=_escape(title),
            lat=center["latitude"], lon=center["longitude"],
            layers_json=data)


def _escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


_LEAFLET_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>html,body,#map{{height:100%;margin:0}}</style></head>
<body><div id="map"></div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
var map = L.map('map').setView([{lat}, {lon}], 4);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
  maxZoom: 19,
  attribution: '&copy; OpenStreetMap contributors'
}}).addTo(map);
var layers = {layers_json};
var group = L.featureGroup().addTo(map);
layers.forEach(function(layer) {{
  L.geoJSON(layer.data, {{
    style: layer.style || {{}},
    pointToLayer: function(f, latlng) {{
      return L.circleMarker(latlng, {{radius: 6, color: (layer.style&&layer.style.color)||'#3388ff'}});
    }},
    onEachFeature: function(f, l) {{
      var p = f.properties || {{}};
      l.bindPopup('<b>'+(p.name||p.entity_id||layer.name)+'</b><br>'+
        Object.keys(p).map(function(k){{return k+': '+p[k];}}).join('<br>'));
    }}
  }}).addTo(group);
}});
try {{ map.fitBounds(group.getBounds().pad(0.2)); }} catch(e) {{}}
</script></body></html>"""
