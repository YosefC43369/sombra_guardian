"""
osint/ — Authorized-assessment OSINT framework for Sombra Guardian.

SCOPE AND POSTURE
-----------------
This package collects intelligence from PUBLIC sources only (certificate
transparency logs, passive DNS, ASN/BGP data, and reputation/IOC feeds). It
performs no intrusion, exploitation, credential access, or destructive action —
every source is a read of already-public data. It is meant for the same
authorized use as the rest of this repository: assessing infrastructure you own
or have written permission to test.

DELIBERATE SCOPE LINE. This framework is infrastructure- and asset-oriented
(domains, IPs, ASNs, certificates, and their reputation). It is intentionally
NOT a person-profiling / de-anonymization / breach-dossier pipeline for
arbitrary individuals. Breach/exposure checks, where added, are scoped to an
organization's OWN assets and gated behind the repository's existing
authorization tables (scope_policy / redteam engagements), never pointed at an
arbitrary private person.

DESIGN
------
- Async throughout, built on ``httpx`` (already a project dependency) plus the
  standard library. No aiohttp/tenacity/pydantic/orjson are pulled in: the
  repo is stdlib-first and minimal-dependency, so the backbone below provides
  its own rate limiting, retry/backoff, and typed result objects instead.
- Every network call goes through ``osint.utils.async_http.AsyncHTTPClient``,
  which centralizes timeouts, per-host rate limiting, retry with exponential
  backoff + jitter, and structured logging.
- Source modules (``osint/sources/*.py``) are pure data-layer fetchers: they
  take a validated target and return a ``SourceResult``. They never check
  authorization themselves — that is the command layer's job (app.py), exactly
  as ``/bbscan`` calls ``scope_policy.evaluate_target`` before touching a
  target. Keeping the split means a source stays unit-testable in isolation.
"""

from .utils.async_http import AsyncHTTPClient, RateLimiter, HTTPResult, HAVE_HTTPX
from .sources.base import Source, SourceResult, SourceStatus

__all__ = [
    "AsyncHTTPClient",
    "RateLimiter",
    "HTTPResult",
    "HAVE_HTTPX",
    "Source",
    "SourceResult",
    "SourceStatus",
]

__version__ = "2.0.0-dev"
