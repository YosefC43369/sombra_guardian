"""
geo_osint.geocoding.place_resolver — unify every "what/where is this place" query,
with multilingual and historical alias handling (spec §33–35).

A :class:`PlaceResolver` takes an arbitrary place token — a coordinate in any
format, a country, a city (in any supported language or under a historical name),
or an airport code via an injected resolver — and returns the best
:class:`ResolvedLocation`, recording which alias/name matched. It also exposes the
alias engine directly:

  * :meth:`canonicalize` — "Krung Thep" -> "Bangkok", "Constantinople" ->
    "Istanbul" (spec §34);
  * :meth:`normalize_name` — script/diacritic-folding so multilingual spellings
    collide onto one key (Thai/CJK/Cyrillic/Arabic/Hebrew tolerated; spec §33).

The airport hook is injected (a callable ``code -> ResolvedLocation | None``) to
avoid a hard dependency cycle with the airport engine; when absent, airport codes
simply fall through to the geocoder.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from ..models.location import ResolvedLocation
from ..data import cities as _cities
from .geocoder import Geocoder

AirportResolver = Callable[[str], Optional[ResolvedLocation]]


@dataclass
class PlaceMatch:
    location: ResolvedLocation
    matched_on: str            # the alias/name/code that resolved it
    kind: str                  # "coordinate" | "country" | "city" | "airport" | "alias"

    def to_dict(self) -> dict:
        return {"matched_on": self.matched_on, "kind": self.kind,
                "location": self.location.to_dict()}


class PlaceResolver:
    def __init__(self, geocoder: Optional[Geocoder] = None,
                 airport_resolver: Optional[AirportResolver] = None) -> None:
        self._geo = geocoder or Geocoder()
        self._airport = airport_resolver

    # -- alias engine ------------------------------------------------------
    @staticmethod
    def normalize_name(name: str) -> str:
        """Fold diacritics and case for cross-language matching, *without*
        destroying non-Latin scripts (Thai/CJK/Cyrillic/Arabic/Hebrew survive).

        Only combining marks in the Latin range are stripped, mirroring the
        approach ``airports.py`` already uses, so "São Paulo" == "Sao Paulo" while
        "กรุงเทพ" is preserved intact.
        """
        if not name:
            return ""
        nfkd = unicodedata.normalize("NFKD", name)
        folded = "".join(c for c in nfkd if not (0x0300 <= ord(c) <= 0x036F))
        return " ".join(folded.split()).strip().lower()

    def canonicalize(self, name: str) -> str:
        """Return the canonical place name for an alias, or the input unchanged."""
        canon = _cities.canonical_name(name)
        if canon:
            return canon
        canon = _cities.canonical_name(self.normalize_name(name))
        return canon or name

    # -- unified resolution ------------------------------------------------
    def resolve(self, token: str) -> Optional[PlaceMatch]:
        t = (token or "").strip()
        if not t:
            return None

        # Airport codes (3=IATA, 4=ICAO) when an airport resolver is wired in.
        if self._airport is not None and t.replace(" ", "").isalpha() \
                and len(t) in (3, 4):
            loc = self._airport(t.upper())
            if loc is not None:
                return PlaceMatch(loc, t.upper(), "airport")

        # Canonicalise historical/alt names first.
        canon = self.canonicalize(t)
        results = self._geo.geocode_offline(canon)
        if results:
            loc = results[0]
            kind = "country" if loc.feature_class == "A" else (
                "coordinate" if loc.feature_class == "coordinate" else "city")
            matched = canon if canon.lower() != t.lower() else t
            kind = "alias" if canon.lower() != t.lower() else kind
            return PlaceMatch(loc, matched, kind)

        # Diacritic-folded retry.
        folded = self.normalize_name(t)
        if folded and folded != t.lower():
            results = self._geo.geocode_offline(folded)
            if results:
                return PlaceMatch(results[0], folded, "alias")
        return None

    async def resolve_async(self, token: str,
                            allow_online: bool = True) -> Optional[PlaceMatch]:
        match = self.resolve(token)
        if match is not None:
            return match
        results = await self._geo.geocode(self.canonicalize(token),
                                          allow_online=allow_online)
        if results:
            return PlaceMatch(results[0], token, "city")
        return None
