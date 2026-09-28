"""
web_footprint.analysis.extract — pull structured signals out of public text.

Fed the text of a public page, a public document, or a public repository file,
this module extracts the reconnaissance-relevant references it contains: domains
and subdomains, public IPs, emails, URLs, public-cloud/storage references,
API/documentation references, package references, and "internal-looking" naming
signals (spec §12, §13, §18, §21, §22, §24, §27).

Two safety disciplines, both from the spec and enforced here:

  * SECRET-LIKE MATERIAL IS REDACTED, NEVER USED. If something that looks like a
    credential appears (an AWS key id, a private-key header, a token), it is
    classified and returned in a redacted form only — the raw value is dropped
    on the floor. This module never validates, tests, or transmits a secret
    (spec §24). Redaction happens before any value leaves a function.
  * INTERNAL-NAMING SIGNALS ARE RECON INFORMATION ONLY. A reference to
    ``staging-internal`` or ``vpn.corp.example.com`` is classified as a
    ``PUBLIC_INTERNAL_NAMING_SIGNAL`` (spec §22) — a hint about naming
    conventions, not an invitation to reach anything.

Pure functions, standard library only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .. import normalize

# --- regexes --------------------------------------------------------------- #
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]}]+", re.I)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}\b", re.I)
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Cloud / object-storage reference patterns -> provider label.
_CLOUD_SIGS: List[tuple] = [
    ("aws-s3", re.compile(r"\b([a-z0-9.\-]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\b", re.I)),
    ("aws-s3", re.compile(r"\bs3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9.\-]+)", re.I)),
    ("aws-cloudfront", re.compile(r"\b[a-z0-9]+\.cloudfront\.net\b", re.I)),
    ("azure-blob", re.compile(r"\b([a-z0-9]+)\.blob\.core\.windows\.net\b", re.I)),
    ("azure-web", re.compile(r"\b[a-z0-9\-]+\.azurewebsites\.net\b", re.I)),
    ("gcp-storage", re.compile(r"\bstorage\.googleapis\.com/([a-z0-9._\-]+)", re.I)),
    ("gcp-storage", re.compile(r"\b([a-z0-9._\-]+)\.storage\.googleapis\.com\b", re.I)),
    ("gcp-appspot", re.compile(r"\b[a-z0-9\-]+\.appspot\.com\b", re.I)),
    ("firebase", re.compile(r"\b[a-z0-9\-]+\.(?:firebaseio\.com|firebaseapp\.com)\b", re.I)),
    ("cloudflare-r2", re.compile(r"\b[a-z0-9]+\.r2\.cloudflarestorage\.com\b", re.I)),
    ("digitalocean-spaces", re.compile(r"\b[a-z0-9.\-]+\.digitaloceanspaces\.com\b", re.I)),
    ("vercel", re.compile(r"\b[a-z0-9\-]+\.vercel\.app\b", re.I)),
    ("netlify", re.compile(r"\b[a-z0-9\-]+\.netlify\.app\b", re.I)),
    ("github-pages", re.compile(r"\b[a-z0-9\-]+\.github\.io\b", re.I)),
    ("gitlab-pages", re.compile(r"\b[a-z0-9\-]+\.gitlab\.io\b", re.I)),
    ("heroku", re.compile(r"\b[a-z0-9\-]+\.herokuapp\.com\b", re.I)),
]

# API / documentation reference patterns.
_API_SIGS: List[tuple] = [
    ("openapi", re.compile(r"\b(?:openapi|swagger)(?:\.json|\.ya?ml)?\b", re.I)),
    ("swagger-ui", re.compile(r"/(?:swagger-ui|swagger)(?:/|\.html)", re.I)),
    ("api-docs", re.compile(r"/(?:api-docs|api/docs|apidocs|redoc)\b", re.I)),
    ("graphql", re.compile(r"/graphql\b|\bgraphql\s*endpoint", re.I)),
    ("rest-endpoint", re.compile(r"/api/v[0-9]+(?:/[a-z0-9_\-]+)?", re.I)),
    ("postman", re.compile(r"\b(?:documenter\.getpostman\.com|postman\.com/collections)\b", re.I)),
]

# Package-registry reference patterns -> ecosystem.
_PACKAGE_SIGS: List[tuple] = [
    ("npm", re.compile(r"\bregistry\.npmjs\.org/([@a-z0-9/._\-]+)", re.I)),
    ("npm", re.compile(r"\bnpm\s+(?:install|i)\s+([@a-z0-9/._\-]+)", re.I)),
    ("pypi", re.compile(r"\bpypi\.org/project/([a-z0-9._\-]+)", re.I)),
    ("pypi", re.compile(r"\bpip\s+install\s+([a-z0-9._\-\[\]]+)", re.I)),
    ("maven", re.compile(r"\brepo\d?\.maven\.(?:org|apache\.org)/", re.I)),
    ("nuget", re.compile(r"\bnuget\.org/packages/([a-z0-9._\-]+)", re.I)),
    ("go", re.compile(r"\bgo\s+get\s+([a-z0-9./_\-]+)", re.I)),
    ("rubygems", re.compile(r"\brubygems\.org/gems/([a-z0-9._\-]+)", re.I)),
    ("cargo", re.compile(r"\bcrates\.io/crates/([a-z0-9._\-]+)", re.I)),
]

# CI/CD and container reference patterns (spec §25, §26) -> label.
_PIPELINE_SIGS: List[tuple] = [
    ("github-actions", re.compile(r"\.github/workflows/|uses:\s*[a-z0-9\-]+/", re.I)),
    ("gitlab-ci", re.compile(r"\.gitlab-ci\.yml", re.I)),
    ("jenkins", re.compile(r"\bjenkinsfile\b|jenkins", re.I)),
    ("circleci", re.compile(r"\.circleci/config", re.I)),
    ("travis", re.compile(r"\.travis\.yml", re.I)),
    ("azure-devops", re.compile(r"azure-pipelines\.yml|dev\.azure\.com", re.I)),
    ("docker", re.compile(r"\b(?:dockerfile|docker-compose\.ya?ml|docker\.io/)\b", re.I)),
    ("kubernetes", re.compile(r"\bkind:\s*(?:Deployment|Service|Ingress|Pod)\b|kubectl\b", re.I)),
    ("helm", re.compile(r"\bchart\.ya?ml\b|helm\s+install", re.I)),
]

# "Internal-looking" naming signals (spec §22). These are hints only.
_INTERNAL_HOST_RE = re.compile(
    r"\b[a-z0-9\-]+\.(?:internal|intranet|corp|local|lan|priv|private)\b", re.I)
_INTERNAL_TOKEN_RE = re.compile(
    r"\b(?:[a-z0-9]+[-_])?(?:dev|test|qa|uat|stage|staging|preprod|prod|internal|"
    r"corp|admin|sandbox|dr|backup)(?:[-_][a-z0-9]+)?\b", re.I)

# --- secret-like patterns: matched only to REDACT and classify ------------- #
_SECRET_SIGS: List[tuple] = [
    ("aws-access-key-id", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16})\b")),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("slack-token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b")),
    ("github-token", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{20,})\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")),
    ("generic-secret-assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*[\"']?([^\s\"']{8,})")),
]


def _redact(value: str) -> str:
    """Return a non-usable, shape-preserving redaction of a secret-like value.
    Keeps at most the first 4 characters; the rest becomes asterisks. The raw
    value is never returned or logged."""
    if not value:
        return "****"
    head = value[:4]
    return f"{head}{'*' * min(12, max(4, len(value) - 4))}"


def redact_secrets(text: str) -> List[Dict[str, Any]]:
    """Find secret-like material and return REDACTED classifications only.

    The returned records never contain a usable secret — only its kind and a
    redacted preview (spec §24: REDACT / CLASSIFY / DO NOT VALIDATE / DO NOT
    USE)."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for kind, pat in _SECRET_SIGS:
        for m in pat.finditer(text or ""):
            raw = m.group(1) if m.groups() else m.group(0)
            preview = _redact(raw)
            key = (kind, preview)
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": "secret_signal", "kind": kind,
                        "redacted": preview, "handling": "redacted; not validated"})
    return out


def _within_scope(host: str, base_domain: Optional[str]) -> bool:
    if not base_domain:
        return True
    return normalize.is_subdomain_of(host, base_domain)


def extract(text: str, *, base_domain: Optional[str] = None,
            source: str = "extract", url: str = "") -> List[Dict[str, Any]]:
    """Extract all reference signals from ``text``.

    ``base_domain`` (if given) is used to tag whether a discovered host is within
    the target's registrable domain — not to discard others, but to mark them.
    Returns a flat list of typed records; secret material is redacted."""
    text = text or ""
    out: List[Dict[str, Any]] = []
    base = normalize.registrable_domain(base_domain) if base_domain else None

    def _emit(rec: Dict[str, Any]) -> None:
        rec.setdefault("source", source)
        if url:
            rec.setdefault("seen_at", url)
        out.append(rec)

    # Redact secrets FIRST so nothing downstream can echo a raw value.
    for s in redact_secrets(text):
        _emit(s)

    # URLs and their hosts.
    seen_urls = set()
    for raw in _URL_RE.findall(text):
        nu = normalize.normalize_url(raw)
        if not nu or nu in seen_urls:
            continue
        seen_urls.add(nu)
        _emit({"type": "url", "value": nu})
        host = normalize.host_of_url(nu)
        if host:
            _emit({"type": "subdomain" if (base and host != base) else "domain",
                   "value": host, "within_target": bool(base and _within_scope(host, base))})

    # Bare hostnames.
    seen_hosts = set()
    for raw in _HOST_RE.findall(text):
        host = normalize.normalize_domain(raw)
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        rtype = "subdomain" if (base and host != base and normalize.is_subdomain_of(host, base)) else "domain"
        _emit({"type": rtype, "value": host,
               "within_target": bool(base and _within_scope(host, base))})

    # Emails.
    for raw in set(_EMAIL_RE.findall(text)):
        em = normalize.normalize_email(raw)
        if em:
            _emit({"type": "email", "value": em,
                   "domain": normalize.domain_of_email(em) or ""})

    # Public IPs only (skip private/reserved to avoid internal-network noise).
    for raw in set(_IPV4_RE.findall(text)):
        if normalize.is_public_ip(raw):
            _emit({"type": "ip", "value": normalize.normalize_ip(raw)})

    # Cloud / storage references — classified as PUBLIC_REFERENCE, never tested.
    seen_cloud = set()
    for provider, pat in _CLOUD_SIGS:
        for m in pat.finditer(text):
            ref = m.group(0)
            key = (provider, ref.lower())
            if key in seen_cloud:
                continue
            seen_cloud.add(key)
            _emit({"type": "cloud_reference", "provider": provider,
                   "value": ref, "classification": "PUBLIC_REFERENCE"})

    # API / documentation references.
    seen_api = set()
    for kind, pat in _API_SIGS:
        for m in pat.finditer(text):
            ref = m.group(0)
            key = (kind, ref.lower())
            if key in seen_api:
                continue
            seen_api.add(key)
            _emit({"type": "api_reference", "kind": kind, "value": ref,
                   "classification": "PUBLIC_API_REFERENCE"})

    # Package references.
    seen_pkg = set()
    for eco, pat in _PACKAGE_SIGS:
        for m in pat.finditer(text):
            name = (m.group(1) if m.groups() else m.group(0)).strip()
            key = (eco, name.lower())
            if not name or key in seen_pkg:
                continue
            seen_pkg.add(key)
            _emit({"type": "package_reference", "ecosystem": eco, "value": name})

    # CI/CD & container references.
    seen_pipe = set()
    for label, pat in _PIPELINE_SIGS:
        if pat.search(text) and label not in seen_pipe:
            seen_pipe.add(label)
            _emit({"type": "pipeline_reference", "value": label})

    # Internal-naming signals (hints only).
    seen_internal = set()
    for m in _INTERNAL_HOST_RE.finditer(text):
        ref = m.group(0).lower()
        if ref not in seen_internal:
            seen_internal.add(ref)
            _emit({"type": "internal_naming_signal", "value": ref,
                   "classification": "PUBLIC_INTERNAL_NAMING_SIGNAL"})
    return out
