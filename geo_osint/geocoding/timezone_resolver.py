"""
geo_osint.geocoding.timezone_resolver — map a point or place to an IANA timezone.

Resolution is layered, most-precise first, and every answer states *how* it was
derived so the report can show its precision (spec §32):

  1. **gazetteer** — nearest known place in the offline gazetteer within a small
     radius carries a real IANA zone (highest precision);
  2. **country** — the place's country has a labelled capital zone;
  3. **offset** — as a last resort, a coarse UTC offset from longitude
     (``round(lon / 15)``), returned as an ``Etc/GMT±N`` id and clearly marked
     low-precision.

SCOPE (spec §32): timezone is treated strictly as *environmental metadata* about
a place. It is never used to infer a person's identity, working hours or
location history.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from ..models.coordinate import Coordinate
from ..data import cities as _cities
from ..data import countries as _countries


@dataclass
class TimezoneResult:
    tz: str
    method: str            # "gazetteer" | "country" | "offset"
    confidence: float
    utc_offset_hint: Optional[float] = None

    def to_dict(self) -> dict:
        return {"tz": self.tz, "method": self.method,
                "confidence": round(self.confidence, 3),
                "utc_offset_hint": self.utc_offset_hint}


class TimezoneResolver:
    """Resolve timezones for points and places using offline data only."""

    def __init__(self, gazetteer_radius_km: float = 150.0) -> None:
        self._radius_km = gazetteer_radius_km

    def for_coordinate(self, coord: Coordinate,
                       country_code: str = "") -> TimezoneResult:
        nearest, dist = self._nearest_city(coord)
        if nearest is not None and nearest.timezone and dist <= self._radius_km:
            # closer => higher confidence, capped
            conf = max(0.5, min(0.95, 1.0 - dist / (self._radius_km * 2)))
            return TimezoneResult(nearest.timezone, "gazetteer", conf,
                                  self._offset_hint(coord.longitude))
        cc = country_code or (nearest.country_code if nearest else "")
        if cc:
            tz = _cities.CAPITAL_TZ.get(cc.upper())
            if tz:
                return TimezoneResult(tz, "country", 0.5,
                                      self._offset_hint(coord.longitude))
        offset = round(coord.longitude / 15.0)
        return TimezoneResult(self._etc_gmt(offset), "offset", 0.2, float(offset))

    def for_place(self, name: str, country_code: str = "") -> Optional[TimezoneResult]:
        hits = _cities.find(name, country_code)
        if hits and hits[0].timezone:
            return TimezoneResult(hits[0].timezone, "gazetteer", 0.85)
        cc = country_code or (hits[0].country_code if hits else "")
        if cc:
            tz = _cities.CAPITAL_TZ.get(cc.upper())
            if tz:
                return TimezoneResult(tz, "country", 0.5)
        return None

    def for_country(self, country_code: str) -> Optional[TimezoneResult]:
        tz = _cities.CAPITAL_TZ.get((country_code or "").upper())
        return TimezoneResult(tz, "country", 0.5) if tz else None

    # -- internals ---------------------------------------------------------
    def _nearest_city(self, coord: Coordinate):
        best = None
        best_d = float("inf")
        for c in _cities.all_cities():
            if not c.coordinate:
                continue
            d = coord.distance_km(c.coordinate, method="haversine")
            if d < best_d:
                best_d = d
                best = c
        return best, best_d

    @staticmethod
    def _offset_hint(lon: float) -> float:
        return float(round(lon / 15.0))

    @staticmethod
    def _etc_gmt(offset: int) -> str:
        # Etc/GMT signs are inverted from the usual convention.
        if offset == 0:
            return "Etc/GMT"
        sign = "-" if offset > 0 else "+"
        return f"Etc/GMT{sign}{abs(offset)}"
