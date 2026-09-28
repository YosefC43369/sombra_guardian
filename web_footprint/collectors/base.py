"""
web_footprint.collectors.base — the contract every passive collector implements.

A *collector* reads one public source and returns a :class:`CollectorResult`: a
uniform, serializable envelope of records plus a status. Collectors are the only
part of the engine that touch the network, and every one of them is PASSIVE —
it reads already-public data (certificate transparency, public DNS, public web
archives, the target's own published ``/.well-known`` files). No collector
performs an active probe, an authenticated request, a credential attempt, a
port scan, or any form of rate-limit / CAPTCHA / auth bypass. That boundary is a
property of the collector set, not a runtime toggle.

Design mirrors ``osint.sources.base``: a thin ``run`` wraps ``fetch`` with
timing and a catch-all so one misbehaving source can never break a batch, and
the record-shaping logic lives in a pure ``parse``-style staticmethod that is
unit-tested without a network. Collectors take the shared
``osint.utils.async_http.AsyncHTTPClient`` (so rate limiting, retry and the
request budget are global) but never construct authorization decisions — the
pipeline gates the seed and classifies scope; a collector only fetches what it
is handed.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("modbot.web_footprint.collector")


class CollectorStatus(str, Enum):
    OK = "ok"
    EMPTY = "empty"                  # source answered, nothing found
    RATE_LIMITED = "rate_limited"
    AUTH_REQUIRED = "auth_required"  # a source that needs an API key we lack
    UNAVAILABLE = "unavailable"      # httpx/client missing, or source disabled
    INVALID_TARGET = "invalid_target"
    ERROR = "error"


@dataclass
class CollectorResult:
    """Uniform envelope from any collector."""

    collector: str
    target: str
    status: CollectorStatus
    records: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    elapsed_ms: int = 0
    requests_made: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in (CollectorStatus.OK, CollectorStatus.EMPTY)

    @property
    def count(self) -> int:
        return len(self.records)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector": self.collector, "target": self.target,
            "status": self.status.value, "count": self.count,
            "records": self.records, "reason": self.reason,
            "elapsed_ms": self.elapsed_ms, "requests_made": self.requests_made,
            "meta": self.meta,
        }


class Collector:
    """Base class. Subclasses set ``name`` and implement ``fetch``."""

    name: str = ""
    requires_key: bool = False
    #: which pipeline stage flag (config.stages) turns this collector on
    stage: str = ""

    async def fetch(self, client, target: str,
                    limits: Any = None) -> CollectorResult:  # pragma: no cover
        raise NotImplementedError

    async def run(self, client, target: str, limits: Any = None) -> CollectorResult:
        start = time.monotonic()
        try:
            result = await self.fetch(client, target, limits)
        except Exception as exc:
            logger.exception("collector %s failed on %r", self.name, target)
            result = CollectorResult(self.name, target, CollectorStatus.ERROR,
                                     reason=f"{type(exc).__name__}: {exc}")
        result.elapsed_ms = int((time.monotonic() - start) * 1000)
        return result

    # -- small result constructors ---------------------------------------- #

    def _ok(self, target: str, records: List[Dict[str, Any]],
            **meta: Any) -> CollectorResult:
        status = CollectorStatus.OK if records else CollectorStatus.EMPTY
        return CollectorResult(self.name, target, status, records=records, meta=meta)

    def _empty(self, target: str, reason: str = "") -> CollectorResult:
        return CollectorResult(self.name, target, CollectorStatus.EMPTY, reason=reason)

    def _error(self, target: str, reason: str) -> CollectorResult:
        return CollectorResult(self.name, target, CollectorStatus.ERROR, reason=reason)

    def _invalid(self, target: str, reason: str = "invalid target") -> CollectorResult:
        return CollectorResult(self.name, target, CollectorStatus.INVALID_TARGET,
                               reason=reason)

    def _unavailable(self, target: str, reason: str) -> CollectorResult:
        return CollectorResult(self.name, target, CollectorStatus.UNAVAILABLE,
                               reason=reason)
