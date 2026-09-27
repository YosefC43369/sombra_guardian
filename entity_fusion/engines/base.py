"""
entity_fusion.engines.base — the contract every correlation engine implements.

A *correlation engine* enriches a single entity from information already present
in the record (offline analysis): it derives extra correlation keys, extracts
embedded identifiers (emails/wallets/handles inside a bio), generates handle
variants, or attaches evidence. Engines never make network calls — that is the
job of ``entity_fusion.enrichers``. Keeping the split means an engine is a pure
function of its input and is trivially unit-testable.

``analyze`` returns an ``EngineResult`` carrying:
  * ``derived``  — new metadata keys folded back onto the entity (canonical
                   values, hashes, region hints),
  * ``entities`` — new entities discovered *inside* the record (e.g. an email
                   found in a bio), each linked back to the source entity,
  * ``evidence`` — observed facts to attach for the confidence engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..entity import Entity, Evidence, EntityType


@dataclass
class EngineResult:
    derived: Dict[str, Any] = field(default_factory=dict)
    entities: List[Entity] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)

    def merge_into(self, entity: Entity) -> None:
        """Apply this result to the source entity: fold derived metadata,
        attach evidence. Discovered entities are returned to the caller (the
        pipeline) rather than absorbed, since they are distinct records."""
        for k, v in self.derived.items():
            entity.metadata.setdefault(k, v)
        for ev in self.evidence:
            entity.add_evidence(ev)


class CorrelationEngine:
    """Base class. Subclasses set ``name`` and the entity types they handle,
    and implement ``analyze``."""

    name: str = ""
    handles: tuple = ()      # entity types this engine analyzes

    def can_handle(self, entity: Entity) -> bool:
        return not self.handles or entity.type in self.handles

    def analyze(self, entity: Entity) -> EngineResult:  # pragma: no cover
        raise NotImplementedError

    def run(self, entity: Entity) -> EngineResult:
        """``analyze`` wrapped so a misbehaving engine returns an empty result
        rather than breaking a batch."""
        if not self.can_handle(entity):
            return EngineResult()
        try:
            return self.analyze(entity)
        except Exception:
            import logging
            logging.getLogger("modbot.entity_fusion.engine").exception(
                "engine %s failed on %s", self.name, entity.summary())
            return EngineResult()
