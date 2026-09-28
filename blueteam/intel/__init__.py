"""blueteam.intel — Threat Intel & IOC platform (v0.8.0, passive/defensive).

Layering: ``domain`` (pure) -> ``lookup``/``bloom`` (pure) -> ``feeds`` (parsers
pure, fetch is an adapter) -> ``service`` (orchestration over ports) ->
``adapters`` (SQLite) / ``commands`` (text surface). Import the heavy pieces lazily
so ``import blueteam.intel`` stays cheap and telegram-free.
"""

from .domain import (IOC, IOCType, TLP, canonicalize, detect_type, ioc_id,
                     compute_confidence, to_stix_bundle)
from .lookup import LookupEngine, MatchResult, build_snapshot
from .bloom import BloomFilter

__all__ = ["IOC", "IOCType", "TLP", "canonicalize", "detect_type", "ioc_id",
           "compute_confidence", "to_stix_bundle", "LookupEngine", "MatchResult",
           "build_snapshot", "BloomFilter"]
