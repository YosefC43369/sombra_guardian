"""
geo_osint.geocoding.coordinate_normalizer — one entry point for every coordinate
format the engine accepts, normalising all of them into WGS84 (spec §4).

The heavy lifting lives in :mod:`geo_osint.models.coordinate`; this module is the
analyst-facing facade: detect the format, parse into a :class:`Coordinate`, and
offer batch/stream normalisation and a "describe every representation" helper for
reports. It never invents a value and always preserves precision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from ..models.coordinate import (
    Coordinate, CoordinateParseError, decode_plus_code, mgrs_to_latlon,
    parse_dms, parse_wkt_point, _looks_like_mgrs, _looks_like_plus_code,
)

CoordinateFormat = str  # "decimal" | "dms" | "utm" | "mgrs" | "plus_code" | "wkt" | "geojson"


@dataclass
class NormalizationResult:
    coordinate: Optional[Coordinate]
    detected_format: str
    ok: bool
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "detected_format": self.detected_format,
                "reason": self.reason,
                "coordinate": self.coordinate.to_dict() if self.coordinate else None}


class CoordinateNormalizer:
    """Detect and normalise coordinate strings/objects into WGS84."""

    @staticmethod
    def detect_format(value: Any) -> str:
        if isinstance(value, Coordinate):
            return "coordinate"
        if isinstance(value, (tuple, list)):
            return "decimal"
        if isinstance(value, dict):
            if value.get("type") == "Point":
                return "geojson"
            return "decimal"
        if not isinstance(value, str):
            return "unknown"
        s = value.strip()
        upper = s.upper()
        if upper.startswith("POINT"):
            return "wkt"
        if "+" in s and _looks_like_plus_code(s):
            return "plus_code"
        if _looks_like_mgrs(upper):
            return "mgrs"
        if any(ch in s for ch in "NSEWnsew°'\""):
            return "dms"
        return "decimal"

    def parse(self, value: Any, *, source: str = "") -> Coordinate:
        """Parse a single value into a WGS84 :class:`Coordinate` (raises on failure)."""
        return Coordinate.from_any(value, source=source)

    def normalize(self, value: Any, *, source: str = "") -> NormalizationResult:
        """Non-raising parse: returns a result envelope with the detected format."""
        fmt = self.detect_format(value)
        try:
            coord = Coordinate.from_any(value, source=source or fmt)
            return NormalizationResult(coord, fmt, True)
        except (CoordinateParseError, ValueError, TypeError) as exc:
            return NormalizationResult(None, fmt, False, str(exc))

    def normalize_many(self, values: Iterable[Any]) -> List[NormalizationResult]:
        return [self.normalize(v) for v in values]

    def stream_normalize(self, values: Iterable[Any]) -> Iterator[Coordinate]:
        """Yield only the successfully-parsed coordinates (for large inputs)."""
        for v in values:
            res = self.normalize(v)
            if res.ok and res.coordinate is not None:
                yield res.coordinate

    @staticmethod
    def parse_utm(zone: int, hemisphere: str, easting: float,
                  northing: float) -> Coordinate:
        from ..models.coordinate import utm_to_latlon
        lat, lon = utm_to_latlon(zone, hemisphere, easting, northing)
        return Coordinate(lat, lon, source="utm")

    @staticmethod
    def represent(coord: Coordinate) -> Dict[str, Any]:
        """Every standard representation of a point, for reports/Telegram output."""
        out: Dict[str, Any] = {
            "decimal": [round(coord.latitude, coord.precision or 6),
                        round(coord.longitude, coord.precision or 6)],
            "dms": coord.to_dms(),
            "wkt": coord.to_wkt(),
            "geojson": coord.to_geojson(),
            "plus_code": coord.to_plus_code(),
            "precision_decimals": coord.precision,
            "precision_m": round(coord.precision_m, 2),
        }
        try:
            out["utm"] = str(coord.to_utm())
            out["mgrs"] = coord.to_mgrs()
        except CoordinateParseError as exc:
            out["utm"] = out["mgrs"] = f"n/a ({exc})"
        return out
