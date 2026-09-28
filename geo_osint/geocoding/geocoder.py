"""
geo_osint.geocoding.geocoder — forward geocoding: a name/token -> a location.

Resolution is offline-first (spec §2, §54 "avoid duplicate geocoding logic"):

  1. a raw coordinate (any format) -> parsed and returned directly;
  2. a country token (ISO2/ISO3/name/TLD/calling code) -> the country's capital;
  3. a city/place name or alias (incl. multilingual/historical) -> gazetteer hit;
  4. a fuzzy gazetteer match for near-misses.

When an *online provider* (an OSM/Nominatim adapter implementing
:meth:`geocode`) is supplied and the run mode allows the network, unresolved
queries fall through to it. The provider is optional so the geocoder is fully
testable offline. Multilingual names are normalised via the alias engine and the
gazetteer's alternate names.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any, List, Optional, Protocol

from ..models.coordinate import Coordinate, CoordinateParseError
from ..models.location import AdministrativeLevel, ResolvedLocation
from ..data import cities as _cities
from ..data import countries as _countries
from .coordinate_normalizer import CoordinateNormalizer
from .timezone_resolver import TimezoneResolver


class OnlineGeocoder(Protocol):
    async def geocode(self, query: str, *, limit: int = 1) -> List[ResolvedLocation]:
        ...


class Geocoder:
    """Forward geocoder: resolve a textual place/token to a :class:`ResolvedLocation`."""

    def __init__(self, online: Optional[OnlineGeocoder] = None,
                 fuzzy_min_ratio: float = 0.82) -> None:
        self._online = online
        self._norm = CoordinateNormalizer()
        self._tz = TimezoneResolver()
        self._fuzzy_min = fuzzy_min_ratio

    # -- sync/offline entry point -----------------------------------------
    def geocode_offline(self, query: str) -> List[ResolvedLocation]:
        q = (query or "").strip()
        if not q:
            return []
        # 1) coordinate?
        coord = self._try_coordinate(q)
        if coord is not None:
            return [self._from_coordinate(coord, q)]
        # 2) country token?
        country = _countries.resolve(q)
        if country is not None and country.centroid is not None:
            return [self._from_country(country)]
        # 3) exact city / alias
        hits = _cities.find(q)
        if not hits:
            canon = _cities.canonical_name(q)
            if canon:
                hits = _cities.find(canon)
        if hits:
            return [self._from_city(c) for c in hits]
        # 4) fuzzy
        fuzzy = self._fuzzy_city(q)
        return [self._from_city(c) for c in fuzzy]

    async def geocode(self, query: str, *, limit: int = 5,
                      allow_online: bool = True) -> List[ResolvedLocation]:
        offline = self.geocode_offline(query)
        if offline:
            return offline[:limit]
        if allow_online and self._online is not None:
            try:
                return (await self._online.geocode(query, limit=limit))[:limit]
            except Exception:                       # network failures degrade gracefully
                return []
        return []

    # -- converters --------------------------------------------------------
    def _try_coordinate(self, q: str) -> Optional[Coordinate]:
        res = self._norm.normalize(q)
        return res.coordinate if res.ok else None

    def _from_coordinate(self, coord: Coordinate, query: str) -> ResolvedLocation:
        tz = self._tz.for_coordinate(coord)
        return ResolvedLocation(name=query, coordinate=coord, timezone=tz.tz,
                                feature_class="coordinate", source="coordinate",
                                confidence=0.95)

    def _from_country(self, country) -> ResolvedLocation:
        tz = self._tz.for_country(country.iso2)
        return ResolvedLocation(
            name=country.name, coordinate=country.centroid,
            country_code=country.iso2, country_name=country.name,
            city=country.capital, timezone=tz.tz if tz else "",
            feature_class="A", feature_code="PCLI", source="gazetteer:country",
            confidence=0.9,
            admin_levels=[AdministrativeLevel(0, country.name, country.iso2, "country")],
        )

    def _from_city(self, city) -> ResolvedLocation:
        country = _countries.by_iso2(city.country_code)
        levels = [AdministrativeLevel(0, country.name if country else city.country_code,
                                      city.country_code, "country")]
        if city.admin1:
            levels.append(AdministrativeLevel(1, city.admin1, "", "region"))
        return ResolvedLocation(
            name=city.name, coordinate=city.coordinate,
            country_code=city.country_code,
            country_name=country.name if country else "",
            region=city.admin1, city=city.name, timezone=city.timezone,
            feature_class="P", feature_code=city.feature_code or "PPL",
            population=city.population, alternate_names=list(city.alternate_names),
            source=city.source or "gazetteer:city", confidence=0.88,
            admin_levels=levels,
        )

    def _fuzzy_city(self, q: str, limit: int = 5) -> List[Any]:
        ql = q.lower()
        scored = []
        for c in _cities.all_cities():
            ratio = SequenceMatcher(None, ql, c.name.lower()).ratio()
            for alt in c.alternate_names:
                ratio = max(ratio, SequenceMatcher(None, ql, alt.lower()).ratio())
            if ratio >= self._fuzzy_min:
                scored.append((ratio, c))
        scored.sort(key=lambda t: t[0], reverse=True)
        return [c for _, c in scored[:limit]]
