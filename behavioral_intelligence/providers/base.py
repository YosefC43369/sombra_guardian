"""
behavioral_intelligence.providers.base — the passive-collection provider contract
(spec §52, §54, §55).

Every provider is a polite, read-only client of PUBLIC data. The contract is:

    health_check() -> bool        is the source reachable / configured?
    collect(target) -> raw        fetch public data for a target
    normalize(raw) -> [Observation]   lift into the universal model
    validate(obs) -> bool         drop malformed/out-of-contract records
    rate_limit() -> RateLimiter   the per-host politeness limiter

The base class implements ``run`` (health → collect → normalize → validate) with
a catch-all so one provider can never abort a batch (spec §56); a failure becomes
a status, not an exception. Providers MUST NOT authenticate against, bypass, or
brute-force anything, and MUST honour robots.txt / provider terms / rate limits.
Credentials, where a free tier needs one, come only from the environment.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..models.observation import Observation
from ..configuration import ProviderConfig

logger = logging.getLogger("modbot.behavioral.provider")


class ProviderStatus(str, Enum):
    OK = "ok"
    EMPTY = "empty"
    RATE_LIMITED = "rate_limited"
    AUTH_REQUIRED = "auth_required"
    UNHEALTHY = "unhealthy"
    INVALID_TARGET = "invalid_target"
    ERROR = "error"


@dataclass
class ProviderResult:
    provider: str
    target: str
    status: ProviderStatus
    observations: List[Observation] = field(default_factory=list)
    reason: str = ""
    elapsed_ms: int = 0
    retry_count: int = 0

    @property
    def ok(self) -> bool:
        return self.status in (ProviderStatus.OK, ProviderStatus.EMPTY)

    def to_dict(self) -> Dict[str, Any]:
        return {"provider": self.provider, "target": self.target,
                "status": self.status.value, "count": len(self.observations),
                "reason": self.reason, "elapsed_ms": self.elapsed_ms,
                "retry_count": self.retry_count}


class BehaviorProvider:
    """Base passive provider. Subclasses set ``name``/``kind`` and implement
    ``collect`` (+ optionally ``normalize``/``validate``)."""

    name: str = "base"
    kind: str = "generic"          # account | domain | feed | repository | ...
    requires_key: bool = False

    def __init__(self, config: Optional[ProviderConfig] = None):
        self.config = config or ProviderConfig()
        self._limiter = None

    # -- contract (override) ---------------------------------------------- #

    async def health_check(self) -> bool:
        """Reachable / configured? Default True (no external dependency)."""
        return True

    async def collect(self, target: str) -> Any:  # pragma: no cover - abstract
        raise NotImplementedError

    def normalize(self, raw: Any) -> List[Observation]:
        """Lift raw provider data into Observations. Default: assume raw is
        already a sequence of dict records and use Observation.from_record."""
        out: List[Observation] = []
        for rec in (raw or []):
            if isinstance(rec, Observation):
                out.append(rec)
            elif isinstance(rec, dict):
                out.append(Observation.from_record(rec, source=self.name))
        return out

    def validate(self, obs: Observation) -> bool:
        """Reject records that violate the contract: must have a platform/account
        or a source_url, and must not carry a future timestamp far beyond now."""
        import time
        if not (obs.platform or obs.account_id or obs.source_url):
            return False
        if obs.timestamp and obs.timestamp > time.time() + 86400:
            return False
        return True

    def rate_limit(self):
        """The per-host politeness limiter (lazy; needs the async_http stack)."""
        if self._limiter is None:
            try:
                from osint.utils.async_http import RateLimiter
                self._limiter = RateLimiter(self.config.per_host_rate,
                                            self.config.per_host_burst)
            except Exception:
                self._limiter = None
        return self._limiter

    # -- driver ------------------------------------------------------------ #

    async def run(self, target: str) -> ProviderResult:
        import time
        start = time.monotonic()
        try:
            if not await self.health_check():
                return ProviderResult(self.name, target, ProviderStatus.UNHEALTHY,
                                      elapsed_ms=self._ms(start))
            raw = await self.collect(target)
            obs = [o for o in self.normalize(raw) if self.validate(o)]
            status = ProviderStatus.OK if obs else ProviderStatus.EMPTY
            return ProviderResult(self.name, target, status, observations=obs,
                                  elapsed_ms=self._ms(start))
        except Exception as exc:
            logger.warning("provider %s failed on %r: %s", self.name, target, exc)
            return ProviderResult(self.name, target, ProviderStatus.ERROR,
                                  reason=f"{type(exc).__name__}: {exc}",
                                  elapsed_ms=self._ms(start))

    @staticmethod
    def _ms(start: float) -> int:
        import time
        return int((time.monotonic() - start) * 1000)


# Semantic aliases the spec names (spec §55). They share the base contract;
# subclasses of each specialise their ``kind`` and normalisation.
class ObservationProvider(BehaviorProvider):
    kind = "observation"


class TimelineProvider(BehaviorProvider):
    kind = "timeline"


class LanguageProvider(BehaviorProvider):
    kind = "language"


class TopicProvider(BehaviorProvider):
    kind = "topic"


class InteractionProvider(BehaviorProvider):
    kind = "interaction"
