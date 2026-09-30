"""
cve_tracker.ingestion.fetcher — the HTTP layer with retries, backoff and caching.

One :class:`HttpFetcher` is shared across all sources (rule §32: don't stand up
five HTTP clients). It wraps a single ``httpx.AsyncClient`` and adds:

  * per-source token-bucket rate limiting (:mod:`ratelimit`)
  * exponential backoff with full jitter on retryable failures (5xx, 429,
    timeouts, connection errors), honouring ``Retry-After``
  * conditional requests via stored ETag / Last-Modified, surfacing 304 as a
    cheap 'nothing changed' result
  * a hard response-size ceiling enforced while streaming (decompression-bomb /
    memory-exhaustion guard) — a security control, not a nicety

It never raises ``httpx`` errors outward; everything becomes a typed
:class:`FetchResult` or a :mod:`cve_tracker.errors` exception the retry loop
understands.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import Dict, Optional

from ..constants import ABSOLUTE_MAX_RESPONSE_BYTES
from ..errors import (
    FetchError,
    HTTPStatusError,
    RateLimitedError,
    ResponseTooLargeError,
    TimeoutErrorCVE,
)
from .ratelimit import RateLimiterRegistry

logger = logging.getLogger("modbot.cve.fetcher")

try:
    import httpx
    HAVE_HTTPX = True
except Exception:  # pragma: no cover - environment without httpx
    httpx = None  # type: ignore
    HAVE_HTTPX = False


@dataclass
class FetchResult:
    """Outcome of a single (already-retried) fetch."""

    status: int
    url: str
    content: bytes = b""
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    from_cache: bool = False            # True on a 304 Not Modified
    etag: str = ""
    last_modified: str = ""
    latency_ms: int = 0

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def not_modified(self) -> bool:
        return self.status == 304


class HttpFetcher:
    """Async HTTP client shared across sources. Construct once (per engine run)
    and pass into every source adapter."""

    def __init__(
        self,
        *,
        user_agent: str,
        default_timeout: float = 20.0,
        max_response_bytes: int = 32 * 1024 * 1024,
        max_retries: int = 4,
        retry_base_delay: float = 2.0,
        retry_max_delay: float = 60.0,
        limiters: Optional[RateLimiterRegistry] = None,
    ):
        self.user_agent = user_agent
        self.default_timeout = default_timeout
        self.max_response_bytes = min(max_response_bytes, ABSOLUTE_MAX_RESPONSE_BYTES)
        self.max_retries = max(0, int(max_retries))
        self.retry_base_delay = retry_base_delay
        self.retry_max_delay = retry_max_delay
        self.limiters = limiters or RateLimiterRegistry()
        self._client: Optional["httpx.AsyncClient"] = None

    # ---------------- lifecycle ----------------

    async def __aenter__(self) -> "HttpFetcher":
        self.open()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    def open(self) -> None:
        if not HAVE_HTTPX:
            raise FetchError("httpx is not installed", retryable=False)
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers={"User-Agent": self.user_agent, "Accept": "application/json"},
                timeout=self.default_timeout,
                follow_redirects=True,
            )

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None

    # ---------------- fetch ----------------

    async def fetch_json(self, url: str, **kw):
        """Fetch and parse JSON. Returns (FetchResult, parsed_or_None). A 304
        returns (result, None) with ``from_cache`` set."""
        import json
        result = await self.fetch(url, **kw)
        if result.not_modified or not result.content:
            return result, None
        try:
            data = json.loads(result.content)
        except (json.JSONDecodeError, ValueError) as exc:
            raise FetchError(f"invalid JSON from {url}: {exc}", retryable=False)
        return result, data

    async def fetch(
        self,
        url: str,
        *,
        source: str = "",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        etag: str = "",
        last_modified: str = "",
        rate: float = 1.0,
    ) -> FetchResult:
        """Fetch ``url`` with rate limiting, conditional headers and a retry
        loop. Raises a typed error only after exhausting retries."""
        self.open()
        req_headers = dict(headers or {})
        if etag:
            req_headers["If-None-Match"] = etag
        if last_modified:
            req_headers["If-Modified-Since"] = last_modified

        bucket = self.limiters.get(source or url, rate)
        attempt = 0
        last_exc: Optional[Exception] = None

        while attempt <= self.max_retries:
            attempt += 1
            await bucket.acquire()
            try:
                return await self._do_fetch(
                    url, source=source, headers=req_headers, params=params,
                    timeout=timeout or self.default_timeout,
                )
            except RateLimitedError as exc:
                last_exc = exc
                delay = exc.retry_after if exc.retry_after else self._backoff(attempt)
                self.limiters.penalize(source or url, delay)
                logger.info("CVE FETCH 429 | source=%s | backing off %.1fs (attempt %d)",
                            source, delay, attempt)
            except (FetchError, TimeoutErrorCVE, HTTPStatusError) as exc:
                last_exc = exc
                if getattr(exc, "retryable", False) is False:
                    raise
                delay = self._backoff(attempt)
                logger.info("CVE FETCH RETRY | source=%s | %s | %.1fs (attempt %d)",
                            source, type(exc).__name__, delay, attempt)
            if attempt > self.max_retries:
                break
            await asyncio.sleep(self._backoff(attempt))

        if isinstance(last_exc, Exception):
            raise last_exc
        raise FetchError(f"exhausted retries for {url}", source=source, retryable=True)

    async def _do_fetch(self, url, *, source, headers, params, timeout) -> FetchResult:
        import time as _time
        start = _time.monotonic()
        assert self._client is not None
        try:
            async with self._client.stream(
                "GET", url, headers=headers, params=params, timeout=timeout
            ) as resp:
                status = resp.status_code
                if status == 304:
                    return FetchResult(status=304, url=url, from_cache=True,
                                       headers=dict(resp.headers),
                                       etag=resp.headers.get("ETag", ""),
                                       last_modified=resp.headers.get("Last-Modified", ""),
                                       latency_ms=int((_time.monotonic() - start) * 1000))
                if status == 429:
                    retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                    raise RateLimitedError(f"429 from {url}", source=source,
                                           retry_after=retry_after)
                if status >= 400:
                    raise HTTPStatusError(status, f"{status} from {url}", source=source)

                # Stream with a size ceiling.
                chunks = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise ResponseTooLargeError(
                            f"response from {url} exceeded {self.max_response_bytes} bytes",
                            source=source)
                    chunks.append(chunk)
                content = b"".join(chunks)
                return FetchResult(
                    status=status, url=url, content=content,
                    headers=dict(resp.headers),
                    etag=resp.headers.get("ETag", ""),
                    last_modified=resp.headers.get("Last-Modified", ""),
                    latency_ms=int((_time.monotonic() - start) * 1000),
                )
        except (RateLimitedError, HTTPStatusError, ResponseTooLargeError):
            raise
        except Exception as exc:  # httpx.TimeoutException / ConnectError / etc.
            name = type(exc).__name__.lower()
            if "timeout" in name:
                raise TimeoutErrorCVE(f"timeout fetching {url}", source=source)
            raise FetchError(f"{type(exc).__name__} fetching {url}: {exc}",
                             source=source, retryable=True)

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff with full jitter, capped at retry_max_delay."""
        ceiling = min(self.retry_max_delay, self.retry_base_delay * (2 ** (attempt - 1)))
        return random.uniform(0.0, ceiling)


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    # HTTP-date form: best-effort, fall back to a fixed short delay.
    try:
        from email.utils import parsedate_to_datetime
        import time as _t
        dt = parsedate_to_datetime(value)
        if dt is not None:
            return max(0.0, dt.timestamp() - _t.time())
    except Exception:
        pass
    return None
