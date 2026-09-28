"""
geo_osint.airports.timezone_engine — resolve an airport's IANA timezone.

Prefers the timezone published in the database record; when absent, derives it
from the airport's coordinate via the shared
:class:`~geo_osint.geocoding.TimezoneResolver` (gazetteer -> country -> offset),
carrying the derivation method so the report can show how precise the answer is.
"""

from __future__ import annotations

from typing import Optional

from ..models.airport import Airport
from ..geocoding.timezone_resolver import TimezoneResolver, TimezoneResult


class AirportTimezoneEngine:
    def __init__(self, resolver: Optional[TimezoneResolver] = None) -> None:
        self._tz = resolver or TimezoneResolver()

    def resolve(self, airport: Airport) -> Optional[TimezoneResult]:
        if airport.timezone:
            return TimezoneResult(airport.timezone, "database", 0.95)
        if airport.coordinate is not None:
            return self._tz.for_coordinate(
                airport.coordinate, country_code=airport.country)
        if airport.country:
            return self._tz.for_country(airport.country)
        return None
