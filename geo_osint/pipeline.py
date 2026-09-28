"""
geo_osint.pipeline — the enrichment pipeline over the engine (spec §26, §29, §46).

The engine resolves an entity to observations; the pipeline adds the passive
*enrichment* layer around them:

  * **proximity enrichment** — for each placed observation, attach the nearest
    public infrastructure (airports, cloud regions, seaports) within a radius, as
    additional evidence-backed observations and a proximity summary;
  * **multi-entity correlation** — run several entities and compute their shared
    geography (weak co-location only, never an identity merge — spec §47).

It stays within the run's :class:`~geo_osint.configuration.GeoLimits` (observation
cap, proximity radius) and, like the engine, always returns a result.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .configuration import GeoConfig, GeoMode
from .correlation.geo_entity_correlation import SharedGeography
from .correlation.proximity import ProximityEngine, ProximityResult
from .engine import GeoOSINTEngine, GeoResult
from .infrastructure.cloud_region_engine import CloudRegionEngine
from .models.coordinate import Coordinate
from .models.evidence import Evidence
from .models.observation import GeoObservation, LocationType
from .transport.seaport_engine import SeaportEngine

logger = logging.getLogger("modbot.geo_osint.pipeline")


@dataclass
class PipelineResult:
    result: GeoResult
    proximity: List[ProximityResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"result": self.result.to_dict(),
                "proximity": [p.to_dict() for p in self.proximity]}


class GeoPipeline:
    def __init__(self, config: Optional[GeoConfig] = None,
                 engine: Optional[GeoOSINTEngine] = None) -> None:
        self.config = config or GeoConfig.build(GeoMode.PASSIVE)
        self._engine = engine or GeoOSINTEngine(self.config)
        self._cloud = CloudRegionEngine()
        self._seaports = SeaportEngine()
        self._proximity = ProximityEngine(
            max_radius_km=self.config.limits.max_proximity_radius_km)
        self._proximity.register("airport",
            lambda: [ap for ap in self._engine_airports() if ap.has_fix])
        self._proximity.register("cloud_region", self._cloud.all)
        self._proximity.register("seaport", self._seaports.all)

    def _engine_airports(self):
        # Bounded scan of the airport DB for proximity candidates.
        return list(self._engine._airports._iter_airports())

    async def run(self, entity: str, *, enrich: bool = True) -> PipelineResult:
        result = await self._engine.investigate(entity)
        pres = PipelineResult(result=result)
        if enrich:
            self._enrich(result, pres)
        return pres

    def run_sync(self, entity: str, *, enrich: bool = True) -> PipelineResult:
        result = self._engine.investigate_sync(entity)
        pres = PipelineResult(result=result)
        if enrich:
            self._enrich(result, pres)
        return pres

    def _enrich(self, result: GeoResult, pres: PipelineResult) -> None:
        radius = self.config.limits.default_proximity_radius_km
        cap = self.config.limits.max_observations
        seen_anchor: set = set()
        for obs in list(result.observations.with_fix()):
            if len(result.observations) >= cap:
                break
            anchor = obs.coordinate.rounded(2)
            if anchor in seen_anchor:
                continue
            seen_anchor.add(anchor)
            try:
                prox = self._proximity.search(
                    obs.coordinate, radius_km=radius,
                    categories=["cloud_region", "seaport"], limit_per_category=3)
            except Exception as exc:
                result.errors.append(f"proximity: {exc}")
                continue
            pres.proximity.append(prox)
            for hit in prox.hits:
                coord = getattr(hit.item, "coordinate", None)
                if coord is None:
                    continue
                ev = Evidence(source="proximity",
                              claim=f"{hit.category} '{hit.name}' is "
                                    f"{hit.distance_km} km from {result.entity}",
                              confidence=0.5, precision="public infrastructure",
                              limitations="Proximity is a spatial relationship to "
                                          "public infrastructure, not an ownership "
                                          "or access claim.")
                result.observations.add(GeoObservation(
                    entity_id=result.entity,
                    location_type=_LT.get(hit.category, LocationType.FACILITY),
                    coordinate=coord, source="proximity",
                    city=getattr(hit.item, "city", ""),
                    country_code=getattr(hit.item, "country_code", ""),
                    evidence=[ev],
                    metadata={"proximity_to": result.entity,
                              "distance_km": hit.distance_km, "name": hit.name}))
        # Re-run finalization so profile/score reflect enriched observations.
        self._engine._finalize(result.entity, result)

    async def run_many(self, entities: List[str]) -> Dict[str, Any]:
        results: Dict[str, PipelineResult] = {}
        for e in entities[:self.config.limits.max_entities]:
            results[e] = await self.run(e)
        shared = self._cross_correlate(results)
        return {"entities": {e: r.to_dict() for e, r in results.items()},
                "shared_geography": [s.to_dict() for s in shared]}

    def _cross_correlate(self, results: Dict[str, PipelineResult]) -> List[SharedGeography]:
        keys = list(results)
        out: List[SharedGeography] = []
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                a, b = keys[i], keys[j]
                out.append(self._engine._correlator.shared_geography(
                    a, results[a].result.observations.observations,
                    b, results[b].result.observations.observations))
        return out


_LT = {"cloud_region": LocationType.CLOUD_REGION,
       "seaport": LocationType.SEAPORT, "airport": LocationType.AIRPORT}
