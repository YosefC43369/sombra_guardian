"""
entity_fusion.pipeline — recursive, depth-bounded discovery of linked public
entities, feeding the fusion engine.

The pattern the spec describes (username → website → domain → certificate →
organization → github → email → gravatar → merge) is a graph traversal: each
discovered entity may reveal more entities via an *expander*. This module owns
that traversal generically:

  * An ``Expander`` is any async callable ``(entity, client) -> [Entity]`` that,
    given an entity, returns newly-discovered public entities. The concrete
    enrichers in ``entity_fusion.enrichers`` are expanders; tests supply mock
    expanders, so the traversal logic is verifiable with zero network.
  * Traversal is breadth-first with a hard ``max_depth`` and ``max_entities``
    budget, and a ``visited`` set keyed by ``(type, normalized)`` so cycles
    (A links B links A) terminate.
  * **The authorization gate runs on every entity before it is expanded.** An
    out-of-scope entity is recorded and never triggers a network fetch — scope
    is enforced at the point of expansion, not after the fact.

The pipeline discovers; it does not decide identity. Its output (a set of
entities) is handed to ``FusionEngine.fuse`` for correlation.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

from .entity import Entity
from . import normalization as norm
from .authorization import AuthorizationContext, FusionGate, GateDecision

logger = logging.getLogger("modbot.entity_fusion.pipeline")

# An expander: given an entity (and an optional shared HTTP client), return
# newly-discovered entities. Async so real ones can do network I/O.
Expander = Callable[[Entity, Any], Awaitable[List[Entity]]]


@dataclass
class PipelineConfig:
    max_depth: int = 3
    max_entities: int = 500
    concurrency: int = 8
    per_expansion_timeout: float = 30.0


@dataclass
class PipelineResult:
    discovered: List[Entity] = field(default_factory=list)
    denied: List[GateDecision] = field(default_factory=list)
    depth_reached: int = 0
    expansions: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def elapsed_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    def stats(self) -> Dict[str, Any]:
        return {
            "discovered": len(self.discovered),
            "denied": len(self.denied),
            "depth_reached": self.depth_reached,
            "expansions": self.expansions,
            "elapsed_ms": self.elapsed_ms,
        }


class RecursivePipeline:
    """Breadth-first, scope-gated, budget-bounded entity discovery.

    Register expanders per entity type with ``register`` (or ``add_expander``),
    then ``run`` from one or more seed entities.
    """

    def __init__(self, *, gate: Optional[FusionGate] = None,
                 config: Optional[PipelineConfig] = None):
        self.gate = gate or FusionGate()
        self.config = config or PipelineConfig()
        self._expanders: Dict[str, List[Expander]] = {}

    def register(self, entity_type: str, expander: Expander) -> "RecursivePipeline":
        self._expanders.setdefault(str(entity_type), []).append(expander)
        return self

    # alias
    add_expander = register

    @staticmethod
    def _visit_key(e: Entity) -> str:
        return f"{e.type.value}:{e.normalized or norm.normalize_value(e.type.value, e.value)}"

    async def _expand_one(self, entity: Entity, client: Any) -> List[Entity]:
        expanders = self._expanders.get(entity.type.value, [])
        if not expanders:
            return []
        out: List[Entity] = []
        for expander in expanders:
            try:
                found = await asyncio.wait_for(
                    expander(entity, client),
                    timeout=self.config.per_expansion_timeout)
                out.extend(found or [])
            except asyncio.TimeoutError:
                logger.info("expander timed out for %s", entity.summary())
            except Exception:
                logger.exception("expander failed for %s", entity.summary())
        return out

    async def run(self, seeds: Sequence[Entity], ctx: AuthorizationContext, *,
                  client: Any = None) -> PipelineResult:
        """Traverse from ``seeds`` under scope ``ctx``. Returns everything
        discovered (seeds included) plus the scope denials encountered."""
        result = PipelineResult(started_at=time.monotonic())
        visited: set = set()
        discovered: Dict[str, Entity] = {}
        sem = asyncio.Semaphore(self.config.concurrency)

        # frontier holds (entity, depth)
        frontier: List = []
        for s in seeds:
            if not s.normalized:
                s.normalized = norm.normalize_value(s.type.value, s.value)
            frontier.append((s, 0))

        while frontier and len(discovered) < self.config.max_entities:
            current, depth = frontier.pop(0)
            key = self._visit_key(current)
            if key in visited:
                # merge duplicate discovery into the already-seen entity
                if key in discovered:
                    discovered[key].merge(current, note="pipeline re-discovery")
                continue
            visited.add(key)

            # scope gate: authorize before we keep or expand this entity
            decision = self.gate.authorize(ctx, current)
            if not decision.allowed:
                result.denied.append(decision)
                continue

            discovered[key] = current
            result.depth_reached = max(result.depth_reached, depth)

            if depth >= self.config.max_depth:
                continue

            async def _guarded(ent: Entity):
                async with sem:
                    return await self._expand_one(ent, client)

            children = await _guarded(current)
            result.expansions += 1
            for child in children:
                if not child.normalized:
                    child.normalized = norm.normalize_value(child.type.value, child.value)
                # relationships are set by the expander that produced the child
                frontier.append((child, depth + 1))

        result.discovered = list(discovered.values())
        result.finished_at = time.monotonic()
        return result

    async def discover_and_fuse(self, seeds: Sequence[Entity],
                                ctx: AuthorizationContext, *,
                                client: Any = None, fusion_engine: Any = None):
        """Convenience: run discovery, then fuse the results. ``fusion_engine``
        defaults to a fresh ``FusionEngine`` (imported lazily to avoid a cycle)."""
        pipeline_result = await self.run(seeds, ctx, client=client)
        if fusion_engine is None:
            from .orchestrator import FusionEngine
            fusion_engine = FusionEngine(gate=self.gate)
        fusion_result = fusion_engine.fuse(pipeline_result.discovered, ctx=ctx)
        return pipeline_result, fusion_result
