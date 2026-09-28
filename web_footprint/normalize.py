"""
web_footprint.normalize — canonicalize the identifiers this engine handles.

Reconnaissance quality depends on de-duplication, and de-duplication depends on
canonical forms: ``HTTPS://WWW.Example.com./path`` and ``example.com`` must
collapse to comparable keys before an attack-surface inventory can tell how many
*distinct* assets it actually saw. This module is the single place that decides
those canonical forms.

It layers on ``osint.utils.validators`` (the repo's existing, deliberately strict
domain/IP/ASN normalizer — reused rather than reimplemented) and adds the
web-footprint-specific pieces: URL canonicalization, email/username hygiene, a
best-effort registrable-domain (eTLD+1) reducer, and an "is ``sub`` within
``base``" containment test used all over the pipeline.

Standard library only. Being strict here is a safety property, not just
tidiness — a value that reaches a collector is trusted to be a real, public,
non-SSRF-footgun identifier because it passed through here first.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

# Reuse the repo's existing validators (strict domain/IP/ASN, SSRF-aware).
try:
    from osint.utils import validators as _v
    normalize_domain = _v.normalize_domain
    is_valid_domain = _v.is_valid_domain
    normalize_ip = _v.normalize_ip
    is_valid_ip = _v.is_valid_ip
    is_public_ip = _v.is_public_ip
    normalize_asn = _v.normalize_asn
    is_valid_asn = _v.is_valid_asn
    HAVE_OSINT_VALIDATORS = True
except Exception:  # pragma: no cover - standalone import without osint on path
    HAVE_OSINT_VALIDATORS = False
    import ipaddress as _ip

    _DOMAIN_RE = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

    def normalize_domain(raw):  # type: ignore[no-redef]
        if not raw:
            return None
        t = unicodedata.normalize("NFKC", str(raw)).strip().lower()
        t = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", t)
        t = t.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in t:
            return None
        t = t.split(":", 1)[0].rstrip(".")
        if t.startswith("*."):
            t = t[2:]
        if not t:
            return None
        try:
            t = t.encode("idna").decode("ascii")
        except Exception:
            pass
        return t if _DOMAIN_RE.match(t) else None

    def is_valid_domain(raw):  # type: ignore[no-redef]
        return normalize_domain(raw) is not None

    def normalize_ip(raw):  # type: ignore[no-redef]
        if not raw:
            return None
        try:
            return str(_ip.ip_address(str(raw).strip()))
        except ValueError:
            return None

    def is_valid_ip(raw):  # type: ignore[no-redef]
        return normalize_ip(raw) is not None

    def is_public_ip(raw):  # type: ignore[no-redef]
        s = normalize_ip(raw)
        if s is None:
            return False
        a = _ip.ip_address(s)
        return a.is_global and not a.is_multicast

    def normalize_asn(raw):  # type: ignore[no-redef]
        if not raw:
            return None
        m = re.match(r"^(?:as)?(\d{1,10})$", str(raw).strip(), re.IGNORECASE)
        if not m:
            return None
        v = int(m.group(1))
        return v if 0 < v < 4294967295 else None

    def is_valid_asn(raw):  # type: ignore[no-redef]
        return normalize_asn(raw) is not None


_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,63})$")
_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._\-]{0,38})$")

# A small multi-label public-suffix table. A full PSL is a heavy dependency the
# repo avoids; this covers the common two-label suffixes so eTLD+1 reduction is
# correct for the overwhelming majority of real targets, and falls back to the
# last two labels otherwise (documented, not silent).
_MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "co.za", "org.za", "gov.za",
    "com.sg", "com.hk", "com.tw", "com.mx", "com.tr", "com.ar", "com.pl",
    "co.th", "in.th", "go.th", "or.th", "ac.th",
    "co.kr", "or.kr", "go.kr",
    "com.ua", "gov.ua",
})


def normalize_url(raw: Optional[str]) -> Optional[str]:
    """Canonicalize a URL for de-duplication.

    Lower-cases scheme+host, drops a default port, drops a fragment, collapses a
    bare/trailing-slash path to ``/``, and keeps the query. Returns None for
    anything that is not an http(s) URL with a valid host. Credentials in the
    authority (``user:pass@host``) cause a reject — same footgun stance as the
    domain validator."""
    if not raw:
        return None
    text = unicodedata.normalize("NFKC", str(raw)).strip()
    if "://" not in text:
        text = "http://" + text
    try:
        parts = urlsplit(text)
    except Exception:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    if "@" in (parts.netloc or ""):
        return None
    host = normalize_domain(parts.hostname or "")
    if host is None and is_valid_ip(parts.hostname or ""):
        host = normalize_ip(parts.hostname or "")
    if not host:
        return None
    port = parts.port
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if (port is None or default) else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def host_of_url(raw: Optional[str]) -> Optional[str]:
    """The normalized hostname a URL points at, or None."""
    url = normalize_url(raw)
    if not url:
        return None
    host = urlsplit(url).hostname
    return normalize_domain(host or "") or (normalize_ip(host or "") if host else None)


def normalize_email(raw: Optional[str]) -> Optional[str]:
    """Lower-case and validate an email address; returns the canonical address
    or None. Does not attempt provider-specific canonicalization (dots/plus)."""
    if not raw:
        return None
    text = unicodedata.normalize("NFKC", str(raw)).strip().lower()
    text = text.split("<", 1)[-1].rstrip(">").strip()
    m = _EMAIL_RE.match(text)
    if not m:
        return None
    if normalize_domain(m.group(1)) is None:
        return None
    return text


def domain_of_email(raw: Optional[str]) -> Optional[str]:
    email = normalize_email(raw)
    return normalize_domain(email.split("@", 1)[1]) if email else None


def normalize_username(raw: Optional[str]) -> Optional[str]:
    """A conservative handle normalizer: strip a leading ``@``, lower-case, and
    accept the common ``a-z0-9._-`` handle grammar (2..39 chars)."""
    if not raw:
        return None
    text = unicodedata.normalize("NFKC", str(raw)).strip().lstrip("@").lower()
    return text if _USERNAME_RE.match(text) else None


def registrable_domain(raw: Optional[str]) -> Optional[str]:
    """Best-effort eTLD+1 (the registrable base domain).

    ``api.staging.example.co.uk`` → ``example.co.uk``; ``a.b.example.com`` →
    ``example.com``. Uses the small multi-label suffix table above, falling back
    to the last two labels. This is a heuristic, not a full Public Suffix List
    lookup, and is labelled as such wherever its output feeds a decision."""
    d = normalize_domain(raw)
    if d is None:
        return None
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    last2 = ".".join(labels[-2:])
    last3 = ".".join(labels[-3:])
    if last2 in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return last3
    return last2


def is_subdomain_of(sub: Optional[str], base: Optional[str]) -> bool:
    """True if ``sub`` is ``base`` itself or a name strictly within ``base``."""
    s = normalize_domain(sub)
    b = normalize_domain(base)
    if not s or not b:
        return False
    return s == b or s.endswith("." + b)


def split_host_labels(raw: Optional[str]) -> Tuple[List[str], Optional[str]]:
    """Return (leading-labels, registrable-domain) for a hostname.

    ``api.dev.example.com`` → (["api", "dev"], "example.com"). Useful for
    subdomain-role classification, which only cares about the leading labels."""
    d = normalize_domain(raw)
    if d is None:
        return [], None
    base = registrable_domain(d)
    if base is None or d == base:
        return [], base
    prefix = d[: -(len(base) + 1)]
    return [p for p in prefix.split(".") if p], base
