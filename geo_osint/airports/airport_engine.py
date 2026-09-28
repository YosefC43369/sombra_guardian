"""
geo_osint.airports.airport_engine — the primary consumer of the repo's airport DB.

Spec §5 makes Geo-OSINT the primary consumer of the existing ``airports.py``
Google-Drive/JSON database, *reusing* its streaming search and normalisation
rather than duplicating it. This engine wraps ``airports.py`` and returns typed
:class:`~geo_osint.models.airport.Airport` objects, adding the geospatial
operations the spec asks for:

  * IATA / ICAO / name / city / country lookup (via ``airports.search_stream``);
  * coordinates, elevation, timezone (typed);
  * nearest airports to a point, distance between airports, airport clusters;
  * a place-resolver hook so ``/airport BKK`` resolves through one code path.

STREAMING (spec §5 "search using streaming; never download the full database"):
lookups delegate to ``airports.search_stream`` which streams the JSON. The
whole-DB scans required for nearest/cluster use ``airports._stream_normalized``, a
single generator pass, and are bounded by ``scan_limit`` so a very large database
never fans out without a ceiling. No third-party dependency is introduced.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..models.airport import Airport, Runway
from ..models.coordinate import Coordinate
from ..models.location import ResolvedLocation

logger = logging.getLogger("modbot.geo_osint.airports")

try:                                             # reuse the existing module
    import airports as _airports_db
except Exception:                                # pragma: no cover - repo always has it
    _airports_db = None


class AirportEngine:
    """Typed, geospatial access layer over the repository's airport database."""

    def __init__(self, db: Any = None, scan_limit: int = 100_000) -> None:
        self._db = db if db is not None else _airports_db
        self._scan_limit = scan_limit

    # -- availability ------------------------------------------------------
    @property
    def available(self) -> bool:
        if self._db is None:
            return False
        try:
            return bool(self._db.source_available())
        except Exception:
            return False

    # -- lookups (streaming) ----------------------------------------------
    def search(self, query: str, limit: int = 5) -> List[Airport]:
        """Free-text lookup (IATA/ICAO/name/city/country) via streaming search."""
        if self._db is None or not query:
            return []
        try:
            raw = self._db.search_stream(query, limit=limit)
        except Exception as exc:
            logger.debug("airport search_stream failed: %s", exc)
            try:
                raw = self._db.search_airports(self._db.load_airports(), query, limit=limit)
            except Exception:
                return []
        return [Airport.from_normalized(r) for r in (raw or [])]

    def by_iata(self, code: str) -> Optional[Airport]:
        code = (code or "").strip().upper()
        if len(code) != 3:
            return None
        for ap in self.search(code, limit=8):
            if ap.iata == code:
                return ap
        return None

    def by_icao(self, code: str) -> Optional[Airport]:
        code = (code or "").strip().upper()
        if len(code) != 4:
            return None
        for ap in self.search(code, limit=8):
            if ap.icao == code:
                return ap
        return None

    def by_code(self, code: str) -> Optional[Airport]:
        code = (code or "").strip().upper()
        if len(code) == 3:
            return self.by_iata(code)
        if len(code) == 4:
            return self.by_icao(code)
        return None

    def by_city(self, city: str, limit: int = 10) -> List[Airport]:
        return [ap for ap in self.search(city, limit=limit * 2)
                if ap.city and city.strip().lower() in ap.city.lower()][:limit]

    def by_country(self, country_code: str, limit: int = 50) -> List[Airport]:
        cc = (country_code or "").strip().upper()
        out: List[Airport] = []
        for ap in self._iter_airports():
            if ap.country == cc:
                out.append(ap)
                if len(out) >= limit:
                    break
        return out

    # -- geospatial operations --------------------------------------------
    def distance_km(self, code_a: str, code_b: str) -> Optional[float]:
        a, b = self.by_code(code_a), self.by_code(code_b)
        if a and b:
            return a.distance_km(b)
        return None

    def nearest(self, coord: Coordinate, limit: int = 5,
                max_km: float = 500.0) -> List[Tuple[Airport, float]]:
        """The ``limit`` nearest airports to a point, within ``max_km``."""
        scored: List[Tuple[Airport, float]] = []
        for ap in self._iter_airports():
            if not ap.has_fix:
                continue
            d = coord.distance_km(ap.coordinate, method="haversine")
            if d <= max_km:
                scored.append((ap, round(d, 3)))
        scored.sort(key=lambda t: t[1])
        return scored[:limit]

    def nearest_to_airport(self, code: str, limit: int = 5,
                           max_km: float = 500.0) -> List[Tuple[Airport, float]]:
        base = self.by_code(code)
        if not base or not base.coordinate:
            return []
        out = [(ap, d) for ap, d in self.nearest(base.coordinate, limit + 1, max_km)
               if ap.code != base.code]
        return out[:limit]

    def cluster(self, radius_km: float = 100.0,
                min_size: int = 2, scan_cap: int = 5000) -> List[List[Airport]]:
        """Greedy geographic clustering of airports (single-link within radius).

        A lightweight alternative to the DBSCAN in
        :mod:`geo_osint.correlation.cluster` for the airport domain specifically:
        groups airports whose mutual distance is under ``radius_km``.
        """
        pts = [ap for ap in self._iter_airports() if ap.has_fix][:scan_cap]
        clusters: List[List[Airport]] = []
        used = [False] * len(pts)
        for i, ap in enumerate(pts):
            if used[i]:
                continue
            group = [ap]
            used[i] = True
            for j in range(i + 1, len(pts)):
                if used[j]:
                    continue
                if ap.coordinate.distance_km(pts[j].coordinate, method="haversine") <= radius_km:
                    group.append(pts[j])
                    used[j] = True
            if len(group) >= min_size:
                clusters.append(group)
        clusters.sort(key=len, reverse=True)
        return clusters

    # -- geocoding hook ----------------------------------------------------
    def resolve_place(self, code: str) -> Optional[ResolvedLocation]:
        """Adapter for :class:`~geo_osint.geocoding.PlaceResolver` (code -> location)."""
        ap = self.by_code(code)
        if not ap or not ap.coordinate:
            return None
        return ResolvedLocation(
            name=ap.name or ap.code, coordinate=ap.coordinate,
            country_code=ap.country, city=ap.city, timezone=ap.timezone,
            feature_class="S", feature_code="AIRP", source="airports.json",
            confidence=0.9, metadata={"iata": ap.iata, "icao": ap.icao})

    # -- streaming iterator ------------------------------------------------
    def _iter_airports(self) -> Iterator[Airport]:
        if self._db is None:
            return
        stream = getattr(self._db, "_stream_normalized", None)
        count = 0
        try:
            if callable(stream):
                for rec in stream():
                    yield Airport.from_normalized(rec)
                    count += 1
                    if count >= self._scan_limit:
                        return
            else:
                for rec in self._db.load_airports():
                    yield Airport.from_normalized(rec)
                    count += 1
                    if count >= self._scan_limit:
                        return
        except Exception as exc:
            logger.debug("airport iteration failed: %s", exc)
            return

    def to_feature_collection(self, airports: List[Airport]) -> Dict[str, Any]:
        feats = [ap.to_geojson_feature() for ap in airports if ap.has_fix]
        return {"type": "FeatureCollection",
                "features": [f for f in feats if f is not None]}
