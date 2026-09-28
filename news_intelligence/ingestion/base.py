"""
news_intelligence.ingestion.base — the ingestor contract + polite HTTP layer.

Every ingestor separates two concerns:
  * ``parse(raw, ...)`` — PURE. Turns text/bytes/dict already in hand into an
    ``IngestResult`` (a list of normalized ``Article`` objects + counters). No
    network, so every parser is unit-tested against fixtures offline.
  * ``run(...)`` — I/O. Uses the polite HTTP client (conditional requests via
    ETag/Last-Modified, rate limiting, timeout, configured user-agent) and hands
    each body to ``parse``.

The HTTP client uses ``httpx`` when installed (a project dependency) and falls
back to stdlib ``urllib`` so the module imports and degrades without it.

SECURITY BOUNDARY (spec): this is a passive, read-only public-source collector. It
never authenticates to a paywalled/private resource, never bypasses auth, never
ignores rate limits, and never downloads a malware sample — IOCs are stored as
references only.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models.article import Article

try:
    import httpx  # type: ignore
    HAVE_HTTPX = True
except Exception:  # pragma: no cover
    httpx = None
    HAVE_HTTPX = False


@dataclass
class HTTPResponse:
    status: int
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)
    from_cache: bool = False
    not_modified: bool = False

    @property
    def text(self) -> str:
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return ""

    def header(self, name: str) -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return ""


class RateLimiter:
    def __init__(self, per_minute: float):
        self.min_interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self._last = 0.0

    def wait(self, sleep: Callable[[float], None] = time.sleep) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        delta = now - self._last
        if delta < self.min_interval:
            sleep(self.min_interval - delta)
        self._last = time.monotonic()


class HTTPClient:
    def __init__(self, *, user_agent: str = "SombraGuardian-NI/2.0",
                 timeout: float = 20.0, rate_limit_per_min: float = 30.0):
        self.user_agent = user_agent
        self.timeout = timeout
        self.rate = RateLimiter(rate_limit_per_min)

    def get(self, url: str, *, headers: Optional[Dict[str, str]] = None,
            etag: str = "", last_modified: str = "") -> HTTPResponse:
        self.rate.wait()
        hdrs = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        if etag:
            hdrs["If-None-Match"] = etag
        if last_modified:
            hdrs["If-Modified-Since"] = last_modified
        if HAVE_HTTPX:
            return self._get_httpx(url, hdrs)
        return self._get_urllib(url, hdrs)

    def _get_httpx(self, url: str, hdrs: Dict[str, str]) -> HTTPResponse:  # pragma: no cover
        try:
            r = httpx.get(url, headers=hdrs, timeout=self.timeout,
                          follow_redirects=True)
            return HTTPResponse(status=r.status_code, body=r.content,
                                headers=dict(r.headers),
                                not_modified=(r.status_code == 304))
        except Exception as exc:
            return HTTPResponse(status=0, body=str(exc).encode("utf-8"))

    def _get_urllib(self, url: str, hdrs: Dict[str, str]) -> HTTPResponse:  # pragma: no cover
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return HTTPResponse(status=resp.status, body=resp.read(),
                                    headers={k: v for k, v in resp.headers.items()})
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return HTTPResponse(status=304, not_modified=True)
            return HTTPResponse(status=exc.code, body=str(exc).encode("utf-8"))
        except Exception as exc:
            return HTTPResponse(status=0, body=str(exc).encode("utf-8"))


@dataclass
class IngestResult:
    """Normalized output of one ingestion pass: a set of ``Article`` objects the
    pipeline resolves into stored entities + correlations."""
    provider: str = ""
    articles: List[Article] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    not_modified: bool = False
    fetched: int = 0
    skipped: int = 0

    def extend(self, other: "IngestResult") -> None:
        self.articles.extend(other.articles)
        self.errors.extend(other.errors)
        self.fetched += other.fetched
        self.skipped += other.skipped
        self.not_modified = self.not_modified and other.not_modified

    def summary(self) -> Dict[str, int]:
        return {"provider_articles": len(self.articles), "errors": len(self.errors),
                "fetched": self.fetched, "skipped": self.skipped}


class BaseIngestor:
    """Base: name, category defaults, HTTP client, conditional-fetch helper.

    Subclasses implement ``parse(raw, **kw) -> IngestResult`` (pure) and may
    override ``run(...)`` for the fetch+parse cycle."""

    name = "base"
    default_source_class = "feed"

    def __init__(self, *, http: Optional[HTTPClient] = None,
                 user_agent: str = "SombraGuardian-NI/2.0",
                 timeout: float = 20.0, rate_limit_per_min: float = 30.0,
                 api_key: str = "", max_summary: int = 2000):
        self.http = http or HTTPClient(user_agent=user_agent, timeout=timeout,
                                       rate_limit_per_min=rate_limit_per_min)
        self.api_key = api_key
        self.max_summary = max_summary

    def conditional_get(self, url: str, *, store=None,
                        headers: Optional[Dict[str, str]] = None
                        ) -> Tuple[HTTPResponse, Dict[str, str]]:  # pragma: no cover
        etag = last_modified = ""
        if store is not None:
            state = store.get_provider_state(self.name, url)
            etag = state.get("etag", "")
            last_modified = state.get("last_modified", "")
        resp = self.http.get(url, headers=headers, etag=etag,
                             last_modified=last_modified)
        new_state = {"etag": resp.header("ETag"),
                     "last_modified": resp.header("Last-Modified")}
        if store is not None and resp.status == 200:
            store.set_provider_state(self.name, url, etag=new_state["etag"],
                                     last_modified=new_state["last_modified"])
        return resp, new_state

    def parse(self, raw: Any, **kw) -> IngestResult:  # pragma: no cover
        raise NotImplementedError

    def run(self, *, store=None, **kw) -> IngestResult:  # pragma: no cover
        raise NotImplementedError


__all__ = ["HTTPClient", "HTTPResponse", "RateLimiter", "IngestResult",
           "BaseIngestor", "HAVE_HTTPX"]
