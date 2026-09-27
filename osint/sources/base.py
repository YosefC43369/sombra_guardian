"""
osint.sources.base — the common contract every source module implements.

A Source takes a validated target and returns a SourceResult: a uniform,
serializable envelope carrying the records found, the provider name, timing, and
an explicit status (OK / EMPTY / RATE_LIMITED / AUTH_REQUIRED / ERROR /
INVALID_TARGET). Uniformity lets the orchestrator run many sources concurrently,
merge their results, and report partial failures without special-casing each
provider.
"""

import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.osint.source")


class SourceStatus(str, Enum):
    OK = "ok"
    EMPTY = "empty"                 # provider answered, nothing found
    RATE_LIMITED = "rate_limited"
    AUTH_REQUIRED = "auth_required"  # a free tier that still needs an API key
    INVALID_TARGET = "invalid_target"
    ERROR = "error"


@dataclass
class SourceResult:
    """Uniform result envelope from any source."""
    source: str
    target: str
    status: SourceStatus
    records: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    elapsed_ms: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in (SourceStatus.OK, SourceStatus.EMPTY)

    @property
    def count(self) -> int:
        return len(self.records)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "status": self.status.value,
            "count": self.count,
            "records": self.records,
            "reason": self.reason,
            "elapsed_ms": self.elapsed_ms,
            "meta": self.meta,
        }


class Source:
    """Base class for a source. Subclasses set ``name`` and ``kind`` (the target
    type they accept: 'domain' | 'ip' | 'asn' | ...) and implement ``fetch``.

    ``run`` wraps ``fetch`` with timing and a catch-all so one misbehaving
    provider can never take down a batch — it becomes an ERROR result instead.
    """

    name: str = ""
    kind: str = ""          # target type this source consumes
    requires_key: bool = False

    async def fetch(self, client, target: str) -> SourceResult:  # pragma: no cover
        raise NotImplementedError

    async def run(self, client, target: str) -> SourceResult:
        start = time.monotonic()
        try:
            result = await self.fetch(client, target)
        except Exception as exc:
            logger.exception("OSINT source %s failed on %r", self.name, target)
            result = SourceResult(self.name, target, SourceStatus.ERROR,
                                  reason=f"{type(exc).__name__}: {exc}")
        result.elapsed_ms = int((time.monotonic() - start) * 1000)
        return result

    def _empty(self, target: str, reason: str = "") -> SourceResult:
        return SourceResult(self.name, target, SourceStatus.EMPTY, reason=reason)

    def _error(self, target: str, reason: str) -> SourceResult:
        return SourceResult(self.name, target, SourceStatus.ERROR, reason=reason)

    def _invalid(self, target: str, reason: str = "invalid target") -> SourceResult:
        return SourceResult(self.name, target, SourceStatus.INVALID_TARGET, reason=reason)
