"""
behavioral_intelligence.orchestrator — collection + analysis coordination.

Ties the passive providers, the observation store and the ``BehavioralEngine``
together: collect public observations for an entity from the configured
providers (concurrently, each failure isolated), ingest them (deduplicated),
run the analysis under authorization, persist the results, and return the
``BehaviorProfile``.

Provider isolation (spec §56): one provider failing NEVER aborts the run — its
failure becomes a ``provider_status`` entry on the profile, and analysis proceeds
on whatever was collected.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .configuration import BehavioralConfig, get_config
from .authorization import BehaviorGate, AuthorizationContext, Subject
from .models.observation import Observation, ObservationBatch
from .models.behavior import BehaviorProfile
from .engine import BehavioralEngine
from .storage.observation_store import ObservationStore

logger = logging.getLogger("modbot.behavioral.orchestrator")


@dataclass
class CollectionResult:
    observations: List[Observation] = field(default_factory=list)
    provider_status: List[Dict[str, Any]] = field(default_factory=list)

    def add_status(self, provider: str, status: str, count: int = 0,
                   error: str = "") -> None:
        self.provider_status.append({"provider": provider, "status": status,
                                     "count": count, "error": error})


class BehavioralOrchestrator:
    def __init__(self, *, config: Optional[BehavioralConfig] = None,
                 store: Optional[ObservationStore] = None,
                 gate: Optional[BehaviorGate] = None,
                 providers: Optional[Sequence] = None):
        self.config = config or get_config()
        self.store = store or ObservationStore(db_path=self.config.db_path)
        self.gate = gate or BehaviorGate()
        self.providers = list(providers or [])
        self.engine = BehavioralEngine(config=self.config, gate=self.gate,
                                       store=self.store.store)

    # -- collection -------------------------------------------------------- #

    async def collect(self, target: str, *, subject: Subject = Subject.ACCOUNT
                      ) -> CollectionResult:
        """Run every provider against ``target`` concurrently, isolating
        failures. Returns collected observations + per-provider status."""
        result = CollectionResult()
        if not self.providers:
            result.add_status("(none)", "no_providers")
            return result

        async def run_one(provider) -> None:
            name = getattr(provider, "name", provider.__class__.__name__)
            try:
                healthy = await _maybe_async(provider.health_check)
                if healthy is False:
                    result.add_status(name, "unhealthy")
                    return
                collected = await _maybe_async(provider.collect, target)
                obs = provider.normalize(collected) if hasattr(provider, "normalize") \
                    else list(collected)
                valid = [o for o in obs if provider.validate(o)] \
                    if hasattr(provider, "validate") else list(obs)
                result.observations.extend(valid)
                result.add_status(name, "ok", count=len(valid))
            except Exception as exc:      # provider failure never aborts the run
                logger.warning("provider %s failed on %r: %s", name, target, exc)
                result.add_status(name, "error", error=f"{type(exc).__name__}: {exc}")

        # bounded concurrency
        sem = asyncio.Semaphore(self.config.provider.max_concurrency)

        async def guarded(p):
            async with sem:
                await run_one(p)

        await asyncio.gather(*(guarded(p) for p in self.providers))
        return result

    # -- full run ---------------------------------------------------------- #

    async def run(self, target: str, ctx: AuthorizationContext, *,
                  entity_id: str = "", subject: Subject = Subject.ACCOUNT,
                  persist: bool = True) -> BehaviorProfile:
        """Collect → ingest → analyze → (persist). Authorization is enforced by
        the engine; a denied subject raises PermissionError before any analysis."""
        collection = await self.collect(target, subject=subject)
        for o in collection.observations:
            if entity_id and not o.entity_id:
                o.entity_id = entity_id
        if persist and collection.observations:
            self.store.ingest(collection.observations)

        batch = ObservationBatch(collection.observations,
                                 entity_id=entity_id or target, label=target)
        profile = self.engine.analyze_entity(batch, ctx, subject=subject)
        profile.provider_status = collection.provider_status

        if persist:
            self._persist_results(profile)
        return profile

    def analyze_stored(self, entity_id: str, ctx: AuthorizationContext, *,
                       subject: Subject = Subject.ACCOUNT) -> BehaviorProfile:
        """Analyze observations already in the store (no new collection)."""
        batch = self.store.load_batch(entity_id)
        profile = self.engine.analyze_entity(batch, ctx, subject=subject)
        return profile

    def _persist_results(self, profile: BehaviorProfile) -> None:
        store = self.store.store
        try:
            if profile.anomalies:
                store.save_anomalies(profile.anomalies)
            if profile.change_points:
                store.save_change_points(profile.entity_id, profile.change_points)
            if profile.interactions and profile.interactions.edges:
                store.save_interactions(profile.entity_id,
                                        profile.interactions.edges)
            store.save_snapshot(profile.entity_id, profile.to_dict(),
                                label=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                    time.gmtime()))
        except Exception:
            logger.exception("persisting behavioural results failed (non-fatal)")


async def _maybe_async(fn, *args):
    """Call ``fn`` whether it is sync or async and return its result."""
    result = fn(*args)
    if asyncio.iscoroutine(result):
        return await result
    return result
