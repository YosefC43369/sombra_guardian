"""
cve_tracker.utils.urls — URL normalization and SSRF-conscious validation.

The subsystem stores and displays reference URLs from untrusted sources but
never *fetches* them (only the source adapters fetch, and only their own fixed
API bases). :func:`is_safe_public_url` exists for the one case where an operator
explicitly enables a vendor adapter that follows a configured URL — it rejects
private/link-local/loopback targets so a malicious advisory can't turn the bot
into an SSRF pivot.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

_SCHEME_OK = ("http", "https")
_TRACKING_PARAMS = re.compile(r"^(utm_|fbclid$|gclid$|mc_eid$|mc_cid$)", re.I)


def is_http_url(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        parts = urlsplit(str(value).strip())
    except ValueError:
        return False
    return parts.scheme.lower() in _SCHEME_OK and bool(parts.netloc)


def normalize_url(value: Optional[str]) -> Optional[str]:
    """Trim, lower-case the scheme+host, drop default ports and common tracking
    params, and strip a trailing fragment. Returns None for non-http(s) input.
    Used to make reference de-duplication stable across sources."""
    if not value:
        return None
    raw = str(value).strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme.lower() not in _SCHEME_OK or not parts.netloc:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    host = host.lower().rstrip(".")
    port = parts.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    # Keep userinfo out of stored URLs entirely.
    path = parts.path or ""
    # Drop tracking query params but keep meaningful ones.
    query = ""
    if parts.query:
        kept = []
        for pair in parts.query.split("&"):
            key = pair.split("=", 1)[0]
            if _TRACKING_PARAMS.match(key):
                continue
            kept.append(pair)
        query = "&".join(kept)
    return urlunsplit((scheme, netloc, path, query, ""))


def url_host(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        host = urlsplit(str(value).strip()).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def registrable_domain(value: Optional[str]) -> str:
    """Best-effort eTLD+1 without the public-suffix list dependency: take the
    last two labels, or three for a known two-level ccTLD suffix. Good enough
    for grouping references by 'vendor domain'."""
    host = url_host(value)
    if not host:
        return ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk",
                 "gov.uk", "ac.uk", "com.cn", "net.cn"}
    last_two = ".".join(labels[-2:])
    if last_two in two_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def is_safe_public_url(value: Optional[str]) -> bool:
    """True only for an http(s) URL whose host is NOT an IP literal in a
    private/loopback/link-local/reserved range. A hostname that would need DNS
    is allowed structurally here (the fetch layer applies its own allowlist);
    an IP literal is checked directly. This is an SSRF guard, deliberately
    conservative: unknown/ambiguous → reject."""
    if not is_http_url(value):
        return False
    host = url_host(value)
    if not host:
        return False
    # Reject obvious internal names.
    if host in ("localhost",) or host.endswith(".local") or host.endswith(".internal"):
        return False
    # If host is an IP literal, verify it is globally routable.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not an IP literal → a DNS name; allow at this layer.
        return True
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def normalize_version_host_free(value: Optional[str]) -> Optional[str]:
    """Kept for API symmetry; delegates to normalize_url."""
    return normalize_url(value)
