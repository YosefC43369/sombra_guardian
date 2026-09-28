"""
geo_osint.geocoding.reverse_geocoder — coordinate -> structured location (spec §3).

Offline-first: the nearest gazetteer place and its country supply city, region,
country and timezone; nearby landmarks/airports are attached by the proximity
layer at a higher level. An optional online provider (Nominatim adapter) refines
the result when the run mode allows the network.

HONESTY LINE (spec §3): the engine never infers an address more precise than the
public gazetteer/provider actually offers. A reverse-geocode of a mid-ocean point
returns the nearest coast/country at low confidence, not a fabricated street.
"""

from __future__ import annotations

from typing import Any, List, Optional, Protocol, Tuple

from ..models.coordinate import Coordinate
from ..models.location import AdministrativeLevel, ResolvedLocation
from ..data import cities as _cities
from ..data import countries as _countries
from .timezone_resolver import TimezoneResolver


class OnlineReverseGeocoder(Protocol):
    async def reverse(self, lat: float, lon: float) -> Optional[ResolvedLocation]:
        ...


class ReverseGeocoder:
    """Coordinate -> :class:`ResolvedLocation` using the offline gazetteer."""

    def __init__(self, online: Optional[OnlineReverseGeocoder] = None,
                 max_city_km: float = 250.0) -> None:
        self._online = online
        self._tz = TimezoneResolver()
        self._max_city_km = max_city_km

    def reverse_offline(self, coord: Coordinate) -> ResolvedLocation:
        city, dist = self._nearest_city(coord)
        tz = self._tz.for_coordinate(coord,
                                     country_code=city.country_code if city else "")
        if city is None:
            return ResolvedLocation(name="unknown", coordinate=coord,
                                    timezone=tz.tz, source="reverse:none",
                                    confidence=0.1)
        country = _countries.by_iso2(city.country_code)
        # Confidence falls off with distance from the nearest known place.
        near = dist <= self._max_city_km
        conf = 0.85 if dist <= 25 else (0.6 if near else 0.3)
        levels = [AdministrativeLevel(0, country.name if country else city.country_code,
                                      city.country_code, "country")]
        if city.admin1:
            levels.append(AdministrativeLevel(1, city.admin1, "", "region"))
        return ResolvedLocation(
            name=city.name if dist <= self._max_city_km else (country.name if country else city.name),
            coordinate=coord,
            country_code=city.country_code,
            country_name=country.name if country else "",
            region=city.admin1,
            city=city.name if near else "",
            timezone=tz.tz,
            feature_class="P", source="reverse:gazetteer", confidence=conf,
            admin_levels=levels,
            metadata={"nearest_city": city.name,
                      "nearest_city_km": round(dist, 2),
                      "tz_method": tz.method},
        )

    async def reverse(self, coord: Coordinate, *,
                      allow_online: bool = True) -> ResolvedLocation:
        if allow_online and self._online is not None:
            try:
                online = await self._online.reverse(coord.latitude, coord.longitude)
                if online is not None:
                    if not online.timezone:
                        online.timezone = self._tz.for_coordinate(coord).tz
                    if online.coordinate is None:
                        online.coordinate = coord
                    return online
            except Exception:
                pass
        return self.reverse_offline(coord)

    def _nearest_city(self, coord: Coordinate) -> Tuple[Optional[Any], float]:
        best = None
        best_d = float("inf")
        for c in _cities.all_cities():
            if not c.coordinate:
                continue
            d = coord.distance_km(c.coordinate, method="haversine")
            if d < best_d:
                best_d, best = d, c
        return best, best_d
