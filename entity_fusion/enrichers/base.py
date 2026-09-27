"""
entity_fusion.enrichers.base — the contract for network enrichers.

An *enricher* fetches additional PUBLIC data about an entity from an external
provider and returns newly-discovered entities plus derived metadata/evidence.
Enrichers are the network tier (engines are the offline tier). Each is an async
callable compatible with the pipeline's ``Expander`` signature
(``(entity, client) -> [Entity]``) via ``as_expander``.

All network I/O goes through the OSINT framework's ``AsyncHTTPClient`` so rate
limiting, retries and timeouts are shared with the rest of the platform. httpx
is optional: if it (or the ``osint`` package) is unavailable the enricher
degrades to a no-op that returns nothing, so importing ``entity_fusion`` never
requires the network stack.

Provider API keys, where needed, are read from the environment (never
hard-coded) exactly as ``.env.example`` documents.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, List, Optional

from ..entity import Entity, Evidence

logger = logging.getLogger("modbot.entity_fusion.enricher")

try:
    from osint.utils.async_http import AsyncHTTPClient, HAVE_HTTPX
    HAVE_OSINT_HTTP = True
except Exception:  # pragma: no cover - standalone/degraded
    AsyncHTTPClient = None      # type: ignore
    HAVE_HTTPX = False
    HAVE_OSINT_HTTP = False


@dataclass
class EnrichmentResult:
    derived: dict = field(default_factory=dict)
    entities: List[Entity] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    provider: str = ""
    ok: bool = True
    reason: str = ""

    def apply_to(self, entity: Entity) -> None:
        for k, v in self.derived.items():
            entity.metadata.setdefault(k, v)
        for ev in self.evidence:
            entity.add_evidence(ev)


class Enricher:
    """Base async enricher. Subclasses set ``name``/``handles`` and implement
    ``_fetch``. ``requires_key`` + ``env_key`` declare an optional API key."""

    name: str = ""
    handles: tuple = ()
    requires_key: bool = False
    env_key: str = ""

    def api_key(self) -> str:
        return os.environ.get(self.env_key, "") if self.env_key else ""

    def can_handle(self, entity: Entity) -> bool:
        if self.handles and entity.type not in self.handles:
            return False
        if self.requires_key and not self.api_key():
            return False
        return True

    async def _fetch(self, entity: Entity, client: Any) -> EnrichmentResult:  # pragma: no cover
        raise NotImplementedError

    async def enrich(self, entity: Entity, client: Any = None) -> EnrichmentResult:
        """Public entry: guards availability + handling, wraps ``_fetch`` so a
        provider failure degrades to an empty result instead of raising."""
        if not HAVE_OSINT_HTTP or not HAVE_HTTPX:
            return EnrichmentResult(provider=self.name, ok=False,
                                    reason="httpx/osint HTTP stack unavailable")
        if not self.can_handle(entity):
            return EnrichmentResult(provider=self.name, ok=False,
                                    reason="entity not handled or missing API key")
        owns_client = client is None
        if owns_client:
            client = AsyncHTTPClient(rate=3.0)
            await client.__aenter__()
        try:
            result = await self._fetch(entity, client)
            result.provider = self.name
            return result
        except Exception as exc:
            logger.exception("enricher %s failed", self.name)
            return EnrichmentResult(provider=self.name, ok=False,
                                    reason=f"{type(exc).__name__}: {exc}")
        finally:
            if owns_client:
                await client.__aexit__(None, None, None)

    def as_expander(self):
        """Adapt this enricher to the pipeline's ``Expander`` signature: apply
        derived data to the source entity and return discovered entities."""
        async def _expander(entity: Entity, client: Any) -> List[Entity]:
            result = await self.enrich(entity, client)
            if result.ok:
                result.apply_to(entity)
            return result.entities
        return _expander
