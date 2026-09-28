"""
geo_osint.orchestrator — concurrent multi-entity orchestration (spec §46, §51).

Runs the pipeline over many entities concurrently with a bounded worker pool
(respecting the run's request/entity limits), aggregates their observations into a
single combined view, and computes cross-entity shared geography. This is the
top-level entry the Telegram ``/geo_report`` command and batch jobs call.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .configuration import GeoConfig, GeoMode
from .correlation.geo_entity_correlation import SharedGeography
from .models.observation import ObservationSet
from .pipeline import GeoPipeline, PipelineResult

logger = logging.getLogger("modbot.geo_osint.orchestrator")


@dataclass
class OrchestrationResult:
    results: Dict[str, PipelineResult] = field(default_factory=dict)
    shared_geography: List[SharedGeography] = field(default_factory=list)

    @property
    def combined_observations(self) -> ObservationSet:
        combined = ObservationSet()
        for pres in self.results.values():
            combined.add_all(pres.result.observations.observations)
        return combined

    def to_feature_collection(self) -> Dict[str, Any]:
        return self.combined_observations.to_feature_collection()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_count": len(self.results),
            "observation_count": len(self.combined_observations),
            "entities": {e: r.to_dict() for e, r in self.results.items()},
            "shared_geography": [s.to_dict() for s in self.shared_geography],
        }


class GeoOrchestrator:
    def __init__(self, config: Optional[GeoConfig] = None,
                 concurrency: int = 4) -> None:
        self.config = config or GeoConfig.build(GeoMode.PASSIVE)
        self._pipeline = GeoPipeline(self.config)
        self._concurrency = max(1, concurrency)

    async def run(self, entities: List[str]) -> OrchestrationResult:
        entities = list(dict.fromkeys(entities))[:self.config.limits.max_entities]
        sem = asyncio.Semaphore(self._concurrency)

        async def _one(entity: str) -> tuple:
            async with sem:
                try:
                    return entity, await self._pipeline.run(entity)
                except Exception as exc:
                    logger.exception("orchestrator entity failed: %s", entity)
                    return entity, exc

        gathered = await asyncio.gather(*[_one(e) for e in entities])
        out = OrchestrationResult()
        for entity, res in gathered:
            if isinstance(res, PipelineResult):
                out.results[entity] = res
        out.shared_geography = self._pipeline._cross_correlate(out.results)
        return out

    def run_sync(self, entities: List[str]) -> OrchestrationResult:
        """Offline sync orchestration (no network)."""
        out = OrchestrationResult()
        for e in list(dict.fromkeys(entities))[:self.config.limits.max_entities]:
            try:
                out.results[e] = self._pipeline.run_sync(e)
            except Exception as exc:
                logger.exception("orchestrator sync entity failed: %s", e)
        out.shared_geography = self._pipeline._cross_correlate(out.results)
        return out
