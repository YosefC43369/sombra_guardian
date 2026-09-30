"""
purple_range/attack.py — a thin adapter over the existing ATT&CK engine.

Reuses ``threat_actor_intelligence.mitre.ATTACKEngine`` (seeded offline) to resolve
technique names/tactics for plans and the coverage matrix. Fully defensive: if the engine
is unavailable or a technique isn't in the seed, it degrades to the bare id so nothing
breaks. One catalog per process (the seed is static), lazily loaded.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from .util import normalize_technique

logger = logging.getLogger("modbot.purple_range.attack")


class AttackCatalog:
    def __init__(self):
        self._engine = None
        self._loaded = False

    def _ensure(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            from threat_actor_intelligence.mitre.attack_engine import ATTACKEngine
            self._engine = ATTACKEngine().load_seed()
        except Exception:
            logger.info("ATT&CK engine unavailable; purple_range degrades to id-only")
            self._engine = None

    @property
    def available(self) -> bool:
        self._ensure()
        return self._engine is not None

    def _technique_obj(self, technique_id: str):
        self._ensure()
        if self._engine is None:
            return None
        tid = normalize_technique(technique_id)
        if not tid:
            return None
        try:
            return self._engine.technique(tid) or self._engine.resolve_technique(tid)
        except Exception:
            return None

    def technique_name(self, technique_id: str) -> str:
        obj = self._technique_obj(technique_id)
        return getattr(obj, "name", "") if obj else ""

    def technique_tactics(self, technique_id: str) -> List[str]:
        obj = self._technique_obj(technique_id)
        if not obj:
            return []
        tactics = getattr(obj, "tactics", None) or []
        return [str(t).strip().lower() for t in tactics if t]

    def resolve(self, technique_id: str) -> dict:
        """Best-effort enrichment for a technique; always returns at least the id."""
        tid = normalize_technique(technique_id) or str(technique_id)
        obj = self._technique_obj(technique_id)
        return {
            "technique_id": tid,
            "name": getattr(obj, "name", "") if obj else "",
            "tactics": self.technique_tactics(technique_id),
            "resolved": obj is not None,
        }


_catalog: Optional[AttackCatalog] = None


def get_catalog() -> AttackCatalog:
    global _catalog
    if _catalog is None:
        _catalog = AttackCatalog()
    return _catalog
