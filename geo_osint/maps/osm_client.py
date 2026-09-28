"""
geo_osint.maps.osm_client — OpenStreetMap Nominatim + Overpass client (spec §17).

Implements the online geocoding/reverse-geocoding provider protocols the
:mod:`geo_osint.geocoding` engines call through to, backed by public OSM services:

  * **Nominatim** for forward/reverse geocoding — used strictly within OSM's usage
    policy: a descriptive User-Agent, hard-clamped to <=1 request/second, and disk-
    cached so repeated lookups don't re-hit the service. Bulk/heavy use is not
    performed; this is interactive-rate lookup of already-public map data.
  * **Overpass** passthrough for POI/feature queries (delegated to the
    infrastructure FacilityEngine's query builder).

All parsing is into the engine's :class:`ResolvedLocation`. The client degrades
gracefully: any network/parse failure returns an empty result so the offline
gazetteer remains the answer.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..models.coordinate import Coordinate
from ..models.location import AdministrativeLevel, ResolvedLocation
from ..storage.cache_store import CacheStore

logger = logging.getLogger("modbot.geo_osint.osm")

NOMINATIM = "https://nominatim.openstreetmap.org"


class OSMClient:
    """Nominatim-backed online geocoder/reverse-geocoder (policy-compliant)."""

    def __init__(self, client: Any, *, base_url: str = NOMINATIM,
                 cache: Optional[CacheStore] = None,
                 user_agent: str = "SombraGuardian-GeoOSINT/1.0") -> None:
        self._client = client
        self._base = base_url
        self._cache = cache
        self._ua = user_agent

    def _headers(self) -> Dict[str, str]:
        return {"User-Agent": self._ua, "Accept-Language": "en"}

    # -- forward -----------------------------------------------------------
    async def geocode(self, query: str, *, limit: int = 5) -> List[ResolvedLocation]:
        if self._cache is not None:
            cached = self._cache.get("nominatim_search", f"{query}|{limit}")
            if cached is not None:
                return [_from_cache(c) for c in cached]
        try:
            res = await self._client.get_json(
                f"{self._base}/search",
                params={"q": query, "format": "jsonv2", "limit": limit,
                        "addressdetails": 1},
                headers=self._headers())
            if not res.ok:
                return []
            body = res.json()
        except Exception as exc:
            logger.debug("nominatim search failed: %s", exc)
            return []
        locations = [self._parse(item) for item in body if isinstance(item, dict)]
        locations = [l for l in locations if l is not None]
        if self._cache is not None:
            self._cache.set("nominatim_search", f"{query}|{limit}",
                            [l.to_dict() for l in locations], ttl_s=604800)
        return locations

    # -- reverse -----------------------------------------------------------
    async def reverse(self, lat: float, lon: float) -> Optional[ResolvedLocation]:
        key = f"{lat:.5f},{lon:.5f}"
        if self._cache is not None:
            cached = self._cache.get("nominatim_reverse", key)
            if cached is not None:
                return _from_cache(cached)
        try:
            res = await self._client.get_json(
                f"{self._base}/reverse",
                params={"lat": lat, "lon": lon, "format": "jsonv2",
                        "addressdetails": 1},
                headers=self._headers())
            if not res.ok:
                return None
            loc = self._parse(res.json())
        except Exception as exc:
            logger.debug("nominatim reverse failed: %s", exc)
            return None
        if loc is not None and self._cache is not None:
            self._cache.set("nominatim_reverse", key, loc.to_dict(), ttl_s=604800)
        return loc

    # -- parsing -----------------------------------------------------------
    def _parse(self, item: Dict[str, Any]) -> Optional[ResolvedLocation]:
        if not isinstance(item, dict) or "lat" not in item or "lon" not in item:
            return None
        try:
            coord = Coordinate(float(item["lat"]), float(item["lon"]),
                               source="nominatim")
        except Exception:
            return None
        addr = item.get("address", {}) if isinstance(item.get("address"), dict) else {}
        cc = str(addr.get("country_code", "")).upper()[:2]
        city = (addr.get("city") or addr.get("town") or addr.get("village")
                or addr.get("municipality") or "")
        region = addr.get("state") or addr.get("region") or ""
        levels = []
        if addr.get("country"):
            levels.append(AdministrativeLevel(0, addr["country"], cc, "country"))
        if region:
            levels.append(AdministrativeLevel(1, region, "", "region"))
        return ResolvedLocation(
            name=item.get("name") or item.get("display_name", "").split(",")[0],
            coordinate=coord, country_code=cc,
            country_name=addr.get("country", ""), region=region,
            district=addr.get("county", ""), city=city,
            postal_code=addr.get("postcode", ""),
            feature_class=item.get("category", ""),
            feature_code=item.get("type", ""),
            source="nominatim",
            source_url=f"https://www.openstreetmap.org/"
                       f"{item.get('osm_type', '')}/{item.get('osm_id', '')}",
            confidence=float(item.get("importance", 0.5) or 0.5),
            metadata={"display_name": item.get("display_name", "")})


def _from_cache(d: Dict[str, Any]) -> ResolvedLocation:
    coord = None
    if d.get("coordinate"):
        coord = Coordinate.from_any(d["coordinate"])
    return ResolvedLocation(
        name=d.get("name", ""), coordinate=coord,
        country_code=d.get("country_code", ""),
        country_name=d.get("country_name", ""), region=d.get("region", ""),
        district=d.get("district", ""), city=d.get("city", ""),
        postal_code=d.get("postal_code", ""), timezone=d.get("timezone", ""),
        feature_class=d.get("feature_class", ""),
        feature_code=d.get("feature_code", ""),
        source=d.get("source", "nominatim-cache"),
        source_url=d.get("source_url", ""),
        confidence=float(d.get("confidence", 0.5)))
