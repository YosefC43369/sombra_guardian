"""
osint.utils.async_http — the single network chokepoint for every OSINT source.

Everything the framework fetches goes through here, so timeouts, rate limiting,
retry/backoff and logging are defined once and cannot be forgotten by an
individual source module. Built on httpx (async, already a project dependency)
plus the standard library — no tenacity/aiohttp.

Key pieces
----------
- RateLimiter: an asyncio token-bucket. Per-host limiters keep the framework a
  polite client of free public APIs (crt.sh, BGPView, ...) that will otherwise
  rate-limit or ban an aggressive caller. Tokens refill continuously at
  ``rate`` per second up to ``burst``.
- AsyncHTTPClient: an httpx.AsyncClient wrapper adding retry with exponential
  backoff + full jitter on transient failures (429 / 5xx / network errors),
  honoring a Retry-After header when present, and returning a typed HTTPResult
  instead of raising for ordinary HTTP errors.

Degraded import: httpx is imported defensively so that importing this module
never crashes a bot that (for some reason) lacks httpx; HAVE_HTTPX is exposed
and AsyncHTTPClient raises a clear RuntimeError only when actually used.
"""

import time
import random
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger("modbot.osint.http")

try:
    import httpx
    HAVE_HTTPX = True
except Exception:  # pragma: no cover - environment without httpx
    httpx = None
    HAVE_HTTPX = False

DEFAULT_TIMEOUT = 20.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 0.5      # seconds; delay = base * 2**attempt, then jittered
DEFAULT_BACKOFF_CAP = 20.0
DEFAULT_USER_AGENT = "SombraGuardian-OSINT/2.0 (+authorized-assessment)"
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class RateLimiter:
    """Asyncio token-bucket rate limiter.

    ``rate`` tokens are added per second up to a maximum of ``burst``. Each
    ``acquire()`` waits until a token is available, so N concurrent callers
    sharing one limiter are collectively capped at ``rate`` requests/second.
    """

    def __init__(self, rate: float, burst: Optional[int] = None):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.burst = float(burst if burst is not None else max(1.0, rate))
        self._tokens = self.burst
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._updated = now

    async def acquire(self) -> None:
        # Loop rather than compute-once: another coroutine may take the token we
        # were waiting for, so we recheck after every sleep.
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                wait = deficit / self.rate
            await asyncio.sleep(wait)


@dataclass
class HTTPResult:
    """A completed HTTP attempt. ``ok`` means a response arrived with a 2xx
    status; transport failures and non-2xx both set ok=False with a reason."""
    ok: bool
    status: int = 0
    url: str = ""
    text: str = ""
    reason: str = ""
    attempts: int = 0
    headers: Dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        import json
        return json.loads(self.text)


class AsyncHTTPClient:
    """Async HTTP client with built-in retry/backoff, per-host rate limiting,
    and structured logging. Use as an async context manager:

        async with AsyncHTTPClient(rate=5) as client:
            result = await client.get_json("https://crt.sh/?q=%25.example.com&output=json")
    """

    def __init__(self, *, rate: float = 5.0, burst: Optional[int] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 max_retries: int = DEFAULT_MAX_RETRIES,
                 backoff_base: float = DEFAULT_BACKOFF_BASE,
                 backoff_cap: float = DEFAULT_BACKOFF_CAP,
                 user_agent: str = DEFAULT_USER_AGENT,
                 default_headers: Optional[Dict[str, str]] = None):
        self.rate = rate
        self.burst = burst
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap
        self.user_agent = user_agent
        self.default_headers = dict(default_headers or {})
        self._client = None
        # One limiter per host so a slow provider does not throttle a fast one.
        self._limiters: Dict[str, RateLimiter] = {}

    async def __aenter__(self) -> "AsyncHTTPClient":
        if not HAVE_HTTPX:
            raise RuntimeError("httpx is required for AsyncHTTPClient but is not installed")
        headers = {"User-Agent": self.user_agent, **self.default_headers}
        self._client = httpx.AsyncClient(
            timeout=self.timeout, headers=headers, follow_redirects=True)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _limiter_for(self, url: str) -> RateLimiter:
        try:
            host = httpx.URL(url).host or "_"
        except Exception:
            host = "_"
        if host not in self._limiters:
            self._limiters[host] = RateLimiter(self.rate, self.burst)
        return self._limiters[host]

    def _backoff_delay(self, attempt: int, retry_after: Optional[float]) -> float:
        if retry_after is not None and retry_after >= 0:
            return min(retry_after, self.backoff_cap)
        raw = self.backoff_base * (2 ** attempt)
        return random.uniform(0, min(raw, self.backoff_cap))   # full jitter

    @staticmethod
    def _parse_retry_after(headers) -> Optional[float]:
        value = headers.get("Retry-After") if headers else None
        if not value:
            return None
        try:
            return float(value)   # delta-seconds form; HTTP-date form is ignored
        except (TypeError, ValueError):
            return None

    async def request(self, method: str, url: str, *,
                      params: Optional[dict] = None,
                      headers: Optional[dict] = None) -> HTTPResult:
        """Perform one logical request, retrying transient failures. Returns an
        HTTPResult and never raises for ordinary HTTP/transport errors — the
        caller inspects ``ok``."""
        if self._client is None:
            raise RuntimeError("use AsyncHTTPClient as an async context manager")
        limiter = self._limiter_for(url)
        last_reason = ""
        last_status = 0
        for attempt in range(self.max_retries + 1):
            await limiter.acquire()
            try:
                resp = await self._client.request(method, url, params=params,
                                                  headers=headers)
            except Exception as exc:  # network/DNS/timeout
                last_reason = f"transport error: {type(exc).__name__}: {exc}"
                last_status = 0
                if attempt < self.max_retries:
                    delay = self._backoff_delay(attempt, None)
                    logger.info("OSINT HTTP retry %d/%d %s (%s) in %.2fs",
                                attempt + 1, self.max_retries, url, last_reason, delay)
                    await asyncio.sleep(delay)
                    continue
                return HTTPResult(ok=False, url=url, reason=last_reason,
                                  attempts=attempt + 1)

            last_status = resp.status_code
            if resp.status_code in RETRY_STATUS and attempt < self.max_retries:
                retry_after = self._parse_retry_after(resp.headers)
                delay = self._backoff_delay(attempt, retry_after)
                logger.info("OSINT HTTP retry %d/%d %s (status %d) in %.2fs",
                            attempt + 1, self.max_retries, url, resp.status_code, delay)
                await asyncio.sleep(delay)
                continue

            ok = 200 <= resp.status_code < 300
            return HTTPResult(
                ok=ok, status=resp.status_code, url=str(resp.url),
                text=resp.text, attempts=attempt + 1,
                reason="" if ok else f"HTTP {resp.status_code}",
                headers=dict(resp.headers),
            )
        # Exhausted retries on retryable statuses.
        return HTTPResult(ok=False, status=last_status, url=url,
                          reason=last_reason or f"HTTP {last_status}",
                          attempts=self.max_retries + 1)

    async def get(self, url: str, *, params: Optional[dict] = None,
                  headers: Optional[dict] = None) -> HTTPResult:
        return await self.request("GET", url, params=params, headers=headers)

    async def get_json(self, url: str, *, params: Optional[dict] = None,
                       headers: Optional[dict] = None) -> HTTPResult:
        """GET then require a JSON body. A 2xx with unparseable JSON is turned
        into ok=False so callers get one consistent failure path."""
        result = await self.get(url, params=params, headers=headers)
        if result.ok:
            try:
                result.json()
            except Exception as exc:
                return HTTPResult(ok=False, status=result.status, url=result.url,
                                  reason=f"invalid JSON: {exc}",
                                  attempts=result.attempts, headers=result.headers)
        return result
