"""
geo_osint.maps.naturalearth — offline country/world boundary layers (spec §20).

Natural Earth is public-domain map data. When a Natural Earth (or any) GeoJSON
boundary file is available on disk, this loader indexes its Features by ISO country
code and answers boundary/point-in-country queries entirely offline — no network,
no dependencies. It is deliberately format-tolerant (reads the common
``ISO_A2``/``ISO_A3``/``ADM0_A3``/``iso_a2`` property spellings) so a downloaded
Natural Earth ``ne_*_admin_0_countries.geojson`` works as-is. With no file present,
methods return ``None``/empty and callers fall back to the gazetteer centroids.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from ..models.geofence import BoundingBox, Geofence, _point_in_ring

logger = logging.getLogger("modbot.geo_osint.naturalearth")

_ISO2_KEYS = ("ISO_A2", "iso_a2", "ISO_A2_EH", "WB_A2")
_ISO3_KEYS = ("ISO_A3", "iso_a3", "ADM0_A3", "adm0_a3", "WB_A3", "BRK_A3")
_NAME_KEYS = ("NAME", "name", "ADMIN", "admin", "NAME_LONG", "SOVEREIGNT")


class NaturalEarthLayer:
    def __init__(self, path: str = "") -> None:
        self._by_iso2: Dict[str, Dict[str, Any]] = {}
        self._by_iso3: Dict[str, Dict[str, Any]] = {}
        self._loaded = False
        if path:
            self.load(path)

    @property
    def available(self) -> bool:
        return self._loaded and bool(self._by_iso2 or self._by_iso3)

    def load(self, path: str) -> bool:
        if not os.path.exists(path):
            logger.info("natural earth file not found: %s", path)
            return False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                fc = json.load(fh)
        except (OSError, ValueError) as exc:
            logger.info("natural earth load failed: %s", exc)
            return False
        for feat in fc.get("features", []):
            props = feat.get("properties", {}) or {}
            iso2 = _first(props, _ISO2_KEYS)
            iso3 = _first(props, _ISO3_KEYS)
            if iso2 and iso2 not in ("-99", "-1"):
                self._by_iso2[iso2.upper()] = feat
            if iso3 and iso3 not in ("-99", "-1"):
                self._by_iso3[iso3.upper()] = feat
        self._loaded = True
        return self.available

    def _feature(self, iso: str) -> Optional[Dict[str, Any]]:
        iso = (iso or "").strip().upper()
        if len(iso) == 2:
            return self._by_iso2.get(iso)
        if len(iso) == 3:
            return self._by_iso3.get(iso)
        return None

    def country_geometry(self, iso: str) -> Optional[Dict[str, Any]]:
        feat = self._feature(iso)
        return feat.get("geometry") if feat else None

    def country_geofence(self, iso: str) -> Optional[Geofence]:
        feat = self._feature(iso)
        if not feat:
            return None
        geom = feat.get("geometry", {})
        rings = _outer_rings(geom)
        if not rings:
            return None
        props = feat.get("properties", {})
        name = _first(props, _NAME_KEYS) or iso
        # Use the largest ring as the representative boundary; bbox spans all.
        pts = [(p[1], p[0]) for ring in rings for p in ring]
        bbox = BoundingBox.from_points(pts)
        largest = max(rings, key=len)
        return Geofence(name=name, bbox=bbox, ring=largest, kind="country",
                        source="naturalearth", metadata={"iso": iso.upper()})

    def country_of(self, lat: float, lon: float) -> Optional[str]:
        """Point-in-country lookup over loaded polygons (ISO2)."""
        for iso2, feat in self._by_iso2.items():
            for ring in _outer_rings(feat.get("geometry", {})):
                if _point_in_ring(lon, lat, ring):
                    return iso2
        return None


def _first(props: Dict[str, Any], keys) -> str:
    for k in keys:
        v = props.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def _outer_rings(geom: Dict[str, Any]) -> List[List[List[float]]]:
    t = geom.get("type")
    c = geom.get("coordinates")
    if t == "Polygon" and c:
        return [c[0]]
    if t == "MultiPolygon" and c:
        return [poly[0] for poly in c if poly]
    return []
