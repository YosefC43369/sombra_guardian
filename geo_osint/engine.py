"""
geo_osint.engine — the Geo-OSINT investigation engine (spec §29, §42, §46).

Given an entity — a coordinate, IP, ASN, domain, airport code, country, city or a
free place name — the engine classifies it, runs the relevant subsystems (geocoding,
airports, infrastructure, correlation, the geolocation engines), collects every
finding as an evidence-backed :class:`~geo_osint.models.observation.GeoObservation`,
and consolidates them into an entity<->geography profile, a timeline, an
infrastructure graph, clusters, and an explainable geographic-footprint score.

The engine honours the run :class:`~geo_osint.configuration.GeoConfig`: in LOCAL
mode it never touches the network (offline gazetteer, coordinate math, curated
datasets, airports DB); PASSIVE/DEEP modes add public-source enrichment via the
shared ``osint`` HTTP backbone. Every network path degrades gracefully — a run
always returns a result. No private/live-location capability exists in any mode
(spec §50).
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .configuration import GeoConfig, GeoMode
from .airports.airport_engine import AirportEngine
from .correlation.cluster import ClusterEngine, ClusterResult
from .correlation.geo_entity_correlation import EntityGeoProfile, GeoEntityCorrelator
from .correlation.infrastructure_graph import InfrastructureGraph
from .correlation.timeline import TimelineEngine
from .correlation.ip_geolocation import IPGeolocationEngine
from .correlation.asn_geolocation import ASNGeolocationEngine
from .correlation.domain_geolocation import DomainGeolocationEngine
from .geocoding.coordinate_normalizer import CoordinateNormalizer
from .geocoding.geocoder import Geocoder
from .geocoding.place_resolver import PlaceResolver
from .geocoding.reverse_geocoder import ReverseGeocoder
from .geocoding.timezone_resolver import TimezoneResolver
from .infrastructure.cloud_region_engine import CloudRegionEngine
from .models.coordinate import Coordinate
from .models.evidence import Evidence
from .models.observation import GeoObservation, LocationType, ObservationSet
from .scoring import GeoFootprintScorer

logger = logging.getLogger("modbot.geo_osint.engine")

try:
    from osint.utils import validators as _validators
    from osint.utils.async_http import AsyncHTTPClient, HAVE_HTTPX
except Exception:                                # pragma: no cover
    _validators = None
    AsyncHTTPClient = None
    HAVE_HTTPX = False


class TargetKind(str, Enum):
    COORDINATE = "coordinate"
    IP = "ip"
    ASN = "asn"
    DOMAIN = "domain"
    AIRPORT = "airport"
    COUNTRY = "country"
    PLACE = "place"
    UNKNOWN = "unknown"


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
_ASN_RE = re.compile(r"^AS?\d{1,10}$", re.I)


@dataclass
class GeoResult:
    entity: str
    kind: TargetKind
    config: GeoConfig
    observations: ObservationSet = field(default_factory=ObservationSet)
    profile: Optional[EntityGeoProfile] = None
    timeline: List[Any] = field(default_factory=list)
    graph: Optional[InfrastructureGraph] = None
    clusters: Optional[ClusterResult] = None
    footprint_score: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    @property
    def elapsed_s(self) -> float:
        return round((self.finished_at or time.time()) - self.started_at, 3)

    def to_feature_collection(self) -> Dict[str, Any]:
        return self.observations.to_feature_collection()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity": self.entity, "kind": self.kind.value,
            "config": self.config.to_dict(),
            "elapsed_s": self.elapsed_s,
            "observation_count": len(self.observations),
            "observations": self.observations.to_list(),
            "profile": self.profile.to_dict() if self.profile else None,
            "timeline": [e.to_dict() for e in self.timeline],
            "graph": self.graph.to_dict() if self.graph else None,
            "clusters": self.clusters.to_dict() if self.clusters else None,
            "footprint_score": self.footprint_score,
            "errors": self.errors,
        }


class GeoOSINTEngine:
    def __init__(self, config: Optional[GeoConfig] = None,
                 airport_engine: Optional[AirportEngine] = None) -> None:
        self.config = config or GeoConfig.build(GeoMode.PASSIVE)
        self._norm = CoordinateNormalizer()
        self._airports = airport_engine or AirportEngine()
        self._geocoder = Geocoder()
        self._places = PlaceResolver(self._geocoder,
                                     airport_resolver=self._airports.resolve_place)
        self._reverse = ReverseGeocoder()
        self._tz = TimezoneResolver()
        self._cloud = CloudRegionEngine()
        self._ip = IPGeolocationEngine()
        self._asn = ASNGeolocationEngine()
        self._domain = DomainGeolocationEngine(self._ip)
        self._correlator = GeoEntityCorrelator()
        self._timeline = TimelineEngine()
        self._cluster = ClusterEngine()
        self._scorer = GeoFootprintScorer()

    # -- classification ----------------------------------------------------
    def classify(self, entity: str) -> TargetKind:
        e = (entity or "").strip()
        if not e:
            return TargetKind.UNKNOWN
        if _validators and _validators.is_valid_ip(e):
            return TargetKind.IP
        if _ASN_RE.match(e):
            return TargetKind.ASN
        norm = self._norm.normalize(e)
        if norm.ok and norm.detected_format in ("dms", "mgrs", "plus_code", "wkt") \
                or (norm.ok and "," in e and norm.detected_format == "decimal"):
            return TargetKind.COORDINATE
        if _DOMAIN_RE.match(e):
            return TargetKind.DOMAIN
        if e.isalpha() and len(e) in (3, 4) and self._airports.by_code(e):
            return TargetKind.AIRPORT
        from .data import countries as _c
        if (len(e) in (2, 3) and _c.resolve(e)) or _c.by_name(e):
            return TargetKind.COUNTRY
        return TargetKind.PLACE

    # -- entry points ------------------------------------------------------
    def investigate_sync(self, entity: str,
                         kind: Optional[TargetKind] = None) -> GeoResult:
        """Offline-only investigation (no network, any mode's local capabilities)."""
        kind = kind or self.classify(entity)
        result = GeoResult(entity=entity, kind=kind, config=self.config)
        obs = result.observations
        try:
            self._local_stage(entity, kind, obs, result)
        except Exception as exc:                    # never let one stage kill the run
            logger.exception("local stage failed")
            result.errors.append(f"local stage: {exc}")
        self._finalize(entity, result)
        return result

    async def investigate(self, entity: str,
                          kind: Optional[TargetKind] = None) -> GeoResult:
        kind = kind or self.classify(entity)
        result = GeoResult(entity=entity, kind=kind, config=self.config)
        obs = result.observations
        try:
            self._local_stage(entity, kind, obs, result)
        except Exception as exc:
            logger.exception("local stage failed")
            result.errors.append(f"local stage: {exc}")
        if self.config.mode.uses_network and self.config.limits.max_requests > 0:
            await self._network_stage(entity, kind, obs, result)
        self._finalize(entity, result)
        return result

    # -- local (offline) stage --------------------------------------------
    def _local_stage(self, entity: str, kind: TargetKind,
                     obs: ObservationSet, result: GeoResult) -> None:
        if kind == TargetKind.COORDINATE:
            coord = self._norm.parse(entity)
            loc = self._reverse.reverse_offline(coord)
            obs.add(self._loc_observation(entity, coord, loc, LocationType.COORDINATE))
        elif kind == TargetKind.AIRPORT:
            ap = self._airports.by_code(entity)
            if ap and ap.coordinate:
                obs.add(self._airport_observation(ap))
        elif kind == TargetKind.COUNTRY:
            from .data import countries as _c
            country = _c.resolve(entity)
            if country and country.centroid:
                obs.add(self._country_observation(country))
        elif kind in (TargetKind.PLACE, TargetKind.DOMAIN, TargetKind.IP, TargetKind.ASN):
            match = self._places.resolve(entity)
            if match and match.location.coordinate:
                obs.add(self._loc_observation(
                    entity, match.location.coordinate, match.location,
                    _lt_for_place(match.kind)))
            if kind == TargetKind.DOMAIN:
                for o in self._domain.signals_offline(entity).observations:
                    obs.add(o)

    # -- network stage -----------------------------------------------------
    async def _network_stage(self, entity: str, kind: TargetKind,
                             obs: ObservationSet, result: GeoResult) -> None:
        if AsyncHTTPClient is None or not HAVE_HTTPX:
            result.errors.append("network stage skipped: httpx not available")
            return
        limits = self.config.limits
        try:
            async with AsyncHTTPClient(rate=limits.http_rate, burst=limits.http_burst,
                                       timeout=limits.http_timeout_s,
                                       max_retries=limits.http_max_retries,
                                       user_agent=self.config.user_agent) as client:
                if kind == TargetKind.IP and self.config.source_enabled("ip_geo"):
                    res = await self._ip.locate(entity, client=client)
                    if res.ok and res.observation:
                        obs.add(res.observation)
                elif kind == TargetKind.ASN and self.config.source_enabled("asn_geo"):
                    res = await self._asn.locate(entity, client=client)
                    if res.ok and res.observation:
                        obs.add(res.observation)
                elif kind == TargetKind.DOMAIN and self.config.source_enabled("domain_geo"):
                    dres = await self._domain.locate(entity, client=client)
                    for o in dres.observations:
                        obs.add(o)
                elif kind in (TargetKind.PLACE, TargetKind.COUNTRY) \
                        and self.config.source_enabled("nominatim"):
                    from .maps.osm_client import OSMClient
                    osm = OSMClient(client, user_agent=self.config.user_agent)
                    for loc in await osm.geocode(entity, limit=1):
                        if loc.coordinate:
                            obs.add(self._loc_observation(
                                entity, loc.coordinate, loc, LocationType.LANDMARK))
        except Exception as exc:
            logger.debug("network stage error: %s", exc)
            result.errors.append(f"network stage: {exc}")

    # -- finalization: correlation, timeline, graph, clusters, score ------
    def _finalize(self, entity: str, result: GeoResult) -> None:
        observations = result.observations.observations
        try:
            result.profile = self._correlator.correlate(entity, observations)
        except Exception as exc:
            result.errors.append(f"correlation: {exc}")
        try:
            result.timeline = self._timeline.build(observations)
        except Exception as exc:
            result.errors.append(f"timeline: {exc}")
        try:
            graph = InfrastructureGraph()
            for o in observations:
                graph.add_observation(o)
            result.graph = graph
        except Exception as exc:
            result.errors.append(f"graph: {exc}")
        try:
            placed = result.observations.with_fix()
            if len(placed) >= 3:
                result.clusters = self._cluster.dbscan(
                    placed, eps_km=self.config.limits.default_proximity_radius_km,
                    min_samples=2)
        except Exception as exc:
            result.errors.append(f"clustering: {exc}")
        try:
            result.footprint_score = self._scorer.score(result).to_dict()
        except Exception as exc:
            result.errors.append(f"score: {exc}")
        result.finished_at = time.time()

    # -- observation builders ---------------------------------------------
    def _loc_observation(self, entity: str, coord: Coordinate, loc: Any,
                         lt: LocationType) -> GeoObservation:
        ev = Evidence(source=getattr(loc, "source", "geocoder"),
                      claim=f"{entity} resolved to {getattr(loc, 'display_name', '')}",
                      confidence=float(getattr(loc, "confidence", 0.6)),
                      source_url=getattr(loc, "source_url", ""),
                      precision=f"{coord.precision} decimals")
        return GeoObservation(
            entity_id=entity, location_type=lt, coordinate=coord,
            source=getattr(loc, "source", "geocoder"),
            source_url=getattr(loc, "source_url", ""),
            country_code=getattr(loc, "country_code", ""),
            region=getattr(loc, "region", ""), city=getattr(loc, "city", ""),
            timezone=getattr(loc, "timezone", ""), evidence=[ev])

    def _airport_observation(self, ap: Any) -> GeoObservation:
        ev = Evidence(source="airports.json",
                      claim=f"airport {ap.code} at {ap.city}, {ap.country}",
                      confidence=0.9, precision="airport reference point")
        return GeoObservation(
            entity_id=ap.code or ap.name, location_type=LocationType.AIRPORT,
            coordinate=ap.coordinate, source="airports.json",
            country_code=ap.country, city=ap.city, timezone=ap.timezone,
            evidence=[ev], metadata={"iata": ap.iata, "icao": ap.icao})

    def _country_observation(self, country: Any) -> GeoObservation:
        ev = Evidence(source="gazetteer",
                      claim=f"country {country.name} (capital {country.capital})",
                      confidence=0.9, precision="country centroid (capital)")
        return GeoObservation(
            entity_id=country.iso2, location_type=LocationType.COUNTRY,
            coordinate=country.centroid, source="gazetteer",
            country_code=country.iso2, city=country.capital, evidence=[ev],
            metadata={"iso3": country.iso3})


def _lt_for_place(kind: str) -> LocationType:
    return {"airport": LocationType.AIRPORT, "country": LocationType.COUNTRY,
            "coordinate": LocationType.COORDINATE}.get(kind, LocationType.CITY)
