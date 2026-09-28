"""
geo_osint.infrastructure.cloud_region_engine — public cloud region mapping (spec §11).

Queries the curated public cloud-region dataset
(:mod:`geo_osint.data.cloud_regions`) — the region locations providers publish
themselves — and returns typed :class:`~geo_osint.models.infrastructure.CloudRegion`
objects and evidence-backed observations. Supports lookup by provider, region
code, country, and nearest-region-to-a-point (a common red-team question: "which
cloud regions are closest to this facility/target?"). Coordinates are city-level
by construction; the engine never asserts a physical data-centre location.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..data import cloud_regions as _cr
from ..models.coordinate import Coordinate
from ..models.evidence import Evidence
from ..models.infrastructure import CloudRegion
from ..models.observation import GeoObservation, LocationType

_CLOUD_LIMITATION = (
    "Cloud region coordinates are the provider's published metropolitan area at "
    "city precision; a region spans multiple undisclosed physical data centres and "
    "this is not a rooftop location.")


class CloudRegionEngine:
    def providers(self) -> List[str]:
        return _cr.providers()

    def all(self) -> List[CloudRegion]:
        return _cr.all_regions()

    def by_provider(self, provider: str) -> List[CloudRegion]:
        return _cr.by_provider(provider)

    def by_code(self, code: str) -> Optional[CloudRegion]:
        return _cr.by_code(code)

    def by_country(self, country_code: str) -> List[CloudRegion]:
        cc = (country_code or "").strip().upper()
        return [r for r in _cr.all_regions() if r.country_code == cc]

    def in_city(self, city: str) -> List[CloudRegion]:
        c = (city or "").strip().lower()
        return [r for r in _cr.all_regions() if r.city.lower() == c]

    def nearest(self, coord: Coordinate, limit: int = 5,
                provider: Optional[str] = None,
                max_km: float = 20000.0) -> List[Tuple[CloudRegion, float]]:
        pool = _cr.by_provider(provider) if provider else _cr.all_regions()
        scored = []
        for r in pool:
            if not r.coordinate:
                continue
            d = coord.distance_km(r.coordinate, method="haversine")
            if d <= max_km:
                scored.append((r, round(d, 3)))
        scored.sort(key=lambda t: t[1])
        return scored[:limit]

    def to_observation(self, region: CloudRegion) -> GeoObservation:
        ev = Evidence(
            source="cloud-provider-docs",
            claim=f"{region.provider} region {region.region_code} in "
                  f"{region.city}, {region.country_code}",
            confidence=0.85, source_url=region.source_url,
            precision="city-level (provider-published)",
            limitations=_CLOUD_LIMITATION)
        return GeoObservation(
            entity_id=region.name, location_type=LocationType.CLOUD_REGION,
            coordinate=region.coordinate, source="cloud-provider-docs",
            source_url=region.source_url, country_code=region.country_code,
            city=region.city, evidence=[ev],
            metadata={"provider": region.provider, "region_code": region.region_code})

    def coverage_by_country(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in _cr.all_regions():
            if r.country_code:
                counts[r.country_code] = counts.get(r.country_code, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))

    def to_feature_collection(self, regions: Optional[List[CloudRegion]] = None) -> Dict[str, Any]:
        regs = regions if regions is not None else _cr.all_regions()
        feats = [r.to_geojson_feature() for r in regs if r.coordinate]
        return {"type": "FeatureCollection",
                "features": [f for f in feats if f is not None]}
