"""
threat_actor_intelligence.ingestion.base — the ingestor contract + HTTP layer.

Every ingestor separates two concerns cleanly:
  * ``parse(raw, ...)`` — PURE. Turns bytes/text/dict already in hand into an
    ``IngestResult`` (reports, IOCs, actor/malware/campaign names, techniques).
    No network, so every parser is unit-tested against fixtures offline.
  * ``fetch()`` / ``run()`` — I/O. Uses the polite HTTP client (conditional
    requests via ETag/Last-Modified, rate limiting, timeout, the configured
    user-agent) and hands the body to ``parse``.

The HTTP client uses ``httpx`` when installed (project dependency) and falls back
to stdlib ``urllib`` so the module imports and degrades without it. It records
conditional-request validators through the store's ``provider_state`` so
incremental ingestion only re-processes changed resources (spec INCREMENTAL
INGESTION).

Nothing here fetches non-public resources, bypasses auth, or ignores rate limits
— this is a passive, read-only public-CTI collector (spec SECURITY BOUNDARIES).
"""

from __future__ import annotations

import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models.report import Report
from ..models.ioc import IOC

try:
    import httpx
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
    """Simple per-provider minimum-interval limiter (monotonic clock)."""

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
    def __init__(self, *, user_agent: str = "SombraGuardian-TAI/1.0",
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
                body = resp.read()
                headers = {k: v for k, v in resp.headers.items()}
                return HTTPResponse(status=resp.status, body=body, headers=headers)
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return HTTPResponse(status=304, not_modified=True)
            return HTTPResponse(status=exc.code, body=str(exc).encode("utf-8"))
        except Exception as exc:
            return HTTPResponse(status=0, body=str(exc).encode("utf-8"))

    def post(self, url: str, data: Dict[str, Any], *,
             headers: Optional[Dict[str, str]] = None) -> HTTPResponse:  # pragma: no cover
        self.rate.wait()
        hdrs = {"User-Agent": self.user_agent}
        if headers:
            hdrs.update(headers)
        if HAVE_HTTPX:
            try:
                r = httpx.post(url, data=data, headers=hdrs, timeout=self.timeout,
                               follow_redirects=True)
                return HTTPResponse(status=r.status_code, body=r.content,
                                    headers=dict(r.headers))
            except Exception as exc:
                return HTTPResponse(status=0, body=str(exc).encode("utf-8"))
        import urllib.parse
        payload = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return HTTPResponse(status=resp.status, body=resp.read(),
                                    headers={k: v for k, v in resp.headers.items()})
        except urllib.error.HTTPError as exc:
            return HTTPResponse(status=exc.code, body=exc.read())
        except Exception as exc:
            return HTTPResponse(status=0, body=str(exc).encode("utf-8"))


@dataclass
class IngestResult:
    """Normalized output of one ingestion pass. The pipeline resolves these into
    stored entities + relationships. Kept format-agnostic so every ingestor
    speaks the same language."""
    provider: str = ""
    reports: List[Report] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    actor_names: List[str] = field(default_factory=list)
    malware_names: List[str] = field(default_factory=list)
    campaign_names: List[str] = field(default_factory=list)
    technique_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    # structured objects (populated by STIX/TAXII/API ingestors that yield full
    # entities rather than free text). Typed as Any to avoid a models import cycle
    # here; each holds the concrete model instances from ``..models``.
    actors: List[Any] = field(default_factory=list)
    families: List[Any] = field(default_factory=list)
    campaigns: List[Any] = field(default_factory=list)
    infrastructure: List[Any] = field(default_factory=list)
    relationships: List[Any] = field(default_factory=list)
    raw_objects: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    not_modified: bool = False

    def extend(self, other: "IngestResult") -> None:
        self.reports.extend(other.reports)
        self.iocs.extend(other.iocs)
        self.actor_names.extend(other.actor_names)
        self.malware_names.extend(other.malware_names)
        self.campaign_names.extend(other.campaign_names)
        self.technique_ids.extend(other.technique_ids)
        self.cve_ids.extend(other.cve_ids)
        self.actors.extend(other.actors)
        self.families.extend(other.families)
        self.campaigns.extend(other.campaigns)
        self.infrastructure.extend(other.infrastructure)
        self.relationships.extend(other.relationships)
        self.raw_objects.extend(other.raw_objects)
        self.errors.extend(other.errors)

    def summary(self) -> Dict[str, int]:
        return {"reports": len(self.reports), "iocs": len(self.iocs),
                "actors": len(self.actors) or len(set(self.actor_names)),
                "families": len(self.families) or len(set(self.malware_names)),
                "campaigns": len(self.campaigns) or len(set(self.campaign_names)),
                "infrastructure": len(self.infrastructure),
                "relationships": len(self.relationships),
                "techniques": len(set(self.technique_ids)),
                "cves": len(set(self.cve_ids)), "errors": len(self.errors)}


class BaseIngestor:
    """Base class: name, provider config, HTTP client, conditional-fetch helper.

    Subclasses implement ``parse(raw, **kw) -> IngestResult`` (pure) and may
    override ``run(store=None) -> IngestResult`` for the fetch+parse cycle."""

    name = "base"
    source_class = "unknown"

    def __init__(self, *, http: Optional[HTTPClient] = None,
                 user_agent: str = "SombraGuardian-TAI/1.0",
                 timeout: float = 20.0, rate_limit_per_min: float = 30.0,
                 api_key: str = ""):
        self.http = http or HTTPClient(user_agent=user_agent, timeout=timeout,
                                       rate_limit_per_min=rate_limit_per_min)
        self.api_key = api_key

    # -- conditional fetch (incremental ingestion) ------------------------ #

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

    def run(self, *, store=None) -> IngestResult:  # pragma: no cover
        raise NotImplementedError


__all__ = ["HTTPClient", "HTTPResponse", "RateLimiter", "IngestResult",
           "BaseIngestor", "HAVE_HTTPX"]
