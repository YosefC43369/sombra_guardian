"""
geo_osint.maps.geonames_client — GeoNames gazetteer client (spec §19).

GeoNames is a free public geographical database with rich multilingual/alternate
names. This client queries its public JSON search API (a free username is required
by GeoNames; supplied by the caller) and parses results into the engine's
:class:`~geo_osint.models.city.City`, extending the offline gazetteer. The parser
is a pure function tested offline; the network layer degrades gracefully, and the
offline gazetteer remains the fallback when no username/network is available.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..models.city import City
from ..models.coordinate import Coordinate
from ..storage.cache_store import CacheStore

logger = logging.getLogger("modbot.geo_osint.geonames")

API = "https://secure.geonames.org"


class GeoNamesClient:
    def __init__(self, client: Any = None, username: str = "",
                 cache: Optional[CacheStore] = None) -> None:
        self._client = client
        self._username = username
        self._cache = cache

    @property
    def configured(self) -> bool:
        return bool(self._username)

    def parse_search(self, payload: Dict[str, Any]) -> List[City]:
        out: List[City] = []
        for rec in (payload.get("geonames", []) if isinstance(payload, dict) else []):
            if not isinstance(rec, dict):
                continue
            coord = None
            lat, lon = rec.get("lat"), rec.get("lng")
            if lat is not None and lon is not None:
                try:
                    coord = Coordinate(float(lat), float(lon), source="geonames")
                except Exception:
                    coord = None
            alt = []
            for an in rec.get("alternateNames", []) or []:
                if isinstance(an, dict) and an.get("name"):
                    alt.append(an["name"])
            out.append(City(
                name=str(rec.get("name", "") or rec.get("toponymName", "")),
                coordinate=coord,
                country_code=str(rec.get("countryCode", "")),
                admin1=str(rec.get("adminName1", "")),
                admin2=str(rec.get("adminName2", "")),
                timezone=str((rec.get("timezone") or {}).get("timeZoneId", "")
                             if isinstance(rec.get("timezone"), dict) else ""),
                population=_int(rec.get("population")),
                feature_code=str(rec.get("fcode", "")),
                geonames_id=_int(rec.get("geonameId")),
                alternate_names=alt, source="geonames"))
        return out

    async def search(self, name: str, *, max_rows: int = 5,
                     country: str = "") -> List[City]:
        if not self.configured or self._client is None:
            return []
        cache_key = f"{name}|{country}|{max_rows}"
        if self._cache is not None:
            cached = self._cache.get("geonames_search", cache_key)
            if cached is not None:
                return self.parse_search(cached)
        params = {"q": name, "maxRows": max_rows, "username": self._username,
                  "type": "json", "style": "FULL"}
        if country:
            params["country"] = country.upper()
        try:
            res = await self._client.get_json(f"{API}/searchJSON", params=params)
            if not res.ok:
                return []
            body = res.json()
        except Exception as exc:
            logger.debug("geonames search failed: %s", exc)
            return []
        if self._cache is not None:
            self._cache.set("geonames_search", cache_key, body, ttl_s=604800)
        return self.parse_search(body)


def _int(v: Any) -> Optional[int]:
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None
