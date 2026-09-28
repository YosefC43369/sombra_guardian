"""
geo_osint.transport.aviation_engine — aviation GEOINT facade (spec §6).

Coordinates the aviation-related engines behind one interface for the pipeline and
Telegram commands: airport/heliport/seaplane-base lookup and nearest-airport
(delegated to :class:`~geo_osint.airports.AirportEngine`), runway and timezone
summaries, and airport-network relationships. It collects PUBLIC information only
and, by default, does NOT collect live aircraft surveillance data (spec §6) — there
is no ADS-B / flight-tracking code path here.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..airports.airport_engine import AirportEngine
from ..airports.runway_engine import RunwayEngine
from ..airports.timezone_engine import AirportTimezoneEngine
from ..models.airport import Airport
from ..models.coordinate import Coordinate


class AviationEngine:
    #: Airport kinds this engine surfaces (public aerodrome types).
    KINDS = ("airport", "heliport", "seaplane_base")

    def __init__(self, airport_engine: Optional[AirportEngine] = None) -> None:
        self._airports = airport_engine or AirportEngine()
        self._runways = RunwayEngine()
        self._tz = AirportTimezoneEngine()

    @property
    def collects_live_surveillance(self) -> bool:
        """Always False — this engine never ingests live aircraft tracking (§6)."""
        return False

    def lookup(self, code_or_name: str, limit: int = 5) -> List[Airport]:
        by_code = self._airports.by_code(code_or_name)
        if by_code:
            return [by_code]
        return self._airports.search(code_or_name, limit=limit)

    def profile(self, code: str) -> Optional[Dict[str, Any]]:
        ap = self._airports.by_code(code)
        if ap is None:
            return None
        tz = self._tz.resolve(ap)
        runways = self._runways.summarize(ap)
        return {
            "airport": ap.to_dict(),
            "timezone": tz.to_dict() if tz else None,
            "runways": runways.to_dict(),
            "nearest": [{"code": a.code, "name": a.name, "km": d}
                        for a, d in self._airports.nearest_to_airport(code, limit=5)],
        }

    def nearest(self, coord: Coordinate, limit: int = 5,
                max_km: float = 500.0) -> List[Tuple[Airport, float]]:
        return self._airports.nearest(coord, limit=limit, max_km=max_km)

    def in_country(self, country_code: str, limit: int = 100) -> List[Airport]:
        return self._airports.by_country(country_code, limit=limit)
