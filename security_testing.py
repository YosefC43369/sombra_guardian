"""
security_testing.py — Phase 8: Authorized Security Testing Engine.

Runs a small, fixed set of *passive* web-configuration checks against a
target, and only after scope_policy.evaluate_target() has explicitly
allowed it. Every check is one ordinary unauthenticated request whose
traffic is indistinguishable from a browser loading the page once; the
"testing" is entirely in how the response is read, not in what is sent.

What this module deliberately is NOT, and must never become:
  - No credential attacks, password guessing, brute force, or stuffing.
  - No exploitation, payload generation, RCE, persistence, or privilege
    escalation.
  - No destructive testing, DoS, or traffic flooding.
  - No port scanning, IP-range scanning, or network sweeps. Bare IP and
    CIDR targets are refused outright (see SCANNABLE_TARGET_TYPES) even
    when a scope rule allows them, and only web ports are reachable.
  - No crawling, content discovery, or path guessing. One target in,
    one request out. Nothing is ever harvested from a response and
    fetched in turn.
  - No background or autonomous scanning. Every run starts from an
    explicit authorized request by a named actor.
  - No automatic Finding creation. Results are advisory; a human decides
    whether anything here is worth reporting, through the existing
    findings.create_finding() gate.

Authorization model (unchanged from Phase 4/5, reused not reimplemented):
scope_policy.evaluate_target() is the single source of truth for
Program -> ACTIVE -> Authorization (reviewed + in force) -> normalized
target -> EXCLUDE -> INCLUDE -> deny-by-default. This module calls it
and obeys it. It contains no `is_admin` input anywhere, so chat-admin
status cannot widen what may be tested.

Network guard (stricter than scope on purpose): scope_policy accepts IP
and CIDR targets, so an operator *could* write a scope rule for
127.0.0.1 or 10.0.0.0/8. For a record-keeping system that is harmless;
for an engine that opens sockets it would be an SSRF primitive against
the host running the bot. _forbidden_ip_reason() therefore sits ABOVE
scope and is unconditional: no scope rule, program, or authorization can
re-enable loopback, private, link-local, or cloud-metadata destinations.

Design constraints (matches scope_policy.py / findings.py / bb_case.py):
  - Reuses security.DB_PATH and security.write_audit_log(). No second
    database, no second audit system.
  - CREATE TABLE IF NOT EXISTS only; idempotent init.
  - Every query parameterized.
  - httpx only (already a dependency, used by news.py) plus stdlib
    ssl/socket/asyncio. No shell, no subprocess, no eval/exec.
"""

import ssl
import time
import socket
import sqlite3
import asyncio
import logging
import ipaddress
from dataclass import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

from security import DB_PATH, write_audit_log
from scope_policy import evaluate_target, get_program, normalize_target, TargetType

logger = logging.getLogger(__name__)

try:  # httpx arrives with python-telegram-bot and is used by news.py
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only on a broken install
    httpx = None
    _HTTPX_AVAILABLE = False


# ---------------- Limits (all fixed; never user-supplied) ----------------

REQUEST_TIMEOUT_SECONDS = 10.0
TLS_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 256 * 1024
MAX_REDIRECTS = 5
MAX_CONCURRENT_CHECKS = 2
MAX_REQUESTS_PER_PROGRAM = 60      # per rolling window
MAX_REQUESTS_PER_TARGET = 20       # per rolling window
RATE_LIMIT_WINDOW_SECONDS = 3600

USER_AGENT = "Sombra-Bot-Authorized-Security-Check/1.0"

# Only web ports are reachable. This is what structurally prevents the
# engine from being used as a port prober: there is no code path that
# connects to anything else, whatever the scope rules say.
ALLOWED_PORTS = frozenset({80, 443})
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Scanning a CIDR is network scanning and a bare IP is the shape of IP
# scanning -- both are forbidden by Phase 8 regardless of scope.
SCANNABLE_TARGET_TYPES = frozenset({TargetType.DOMAIN.value, TargetType.URL.value})

_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

# Headers that routinely disclose software versions. Read from the
# response we already have -- nothing is probed to obtain them.
_VERSION_DISCLOSING_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                               "x-aspnetmvc-version", "x-generator", "x-drupal-cache")

_concurrency = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)


# ---------------- Result shapes ----------------

@dataclass
class Observation:
    """One thing noticed in a response. Advisory only: an Observation is
    never promoted to a Finding by this module."""
    severity_hint: str      # INFO / LOW / MEDIUM  (a hint, not a Finding severity)
    code: str
    detail: str = ""


@dataclass
class CheckResult:
    ok: bool
    status: str                       # COMPLETED / DENIED / FAILED
    reason: str = "OK"
    program_id: Optional[int] = None
    target: Optional[str] = None       # normalized, never the raw input
    check_type: Optional[str] = None
    observations: List[Observation] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "reason": self.reason,
            "program_id": self.program_id,
            "target": self.target,
            "check_type": self.check_type,
            "findings": [
                {"severity_hint": o.severity_hint, "code": o.code, "detail": o.detail}
                for o in self.observations
            ],
            "data": self.data,
        }


def _denied(reason: str, program_id=None, target=None, check_type=None) -> CheckResult:
    return CheckResult(ok=False, status="DENIED", reason=reason, program_id=program_id,
                       target=target, check_type=check_type)


def _failed(reason: str, program_id=None, target=None, check_type=None) -> CheckResult:
    return CheckResult(ok=False, status="FAILED", reason=reason, program_id=program_id,
                       target=target, check_type=check_type)


# ---------------- Database (rate limiting only) ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def security_testing_db_init() -> None:
    """Creates the scan rate-limit table only.

    quota.py is deliberately NOT reused here: its tables are ai_usage /
    ai_classifier_usage, keyed per chat+user+day for AI spend. Charging a
    network check against a user's daily AI allowance would be the wrong
    meter on the wrong axis. This table follows quota.py's exact
    allow-then-increment / ON CONFLICT pattern instead, keyed by program
    and target over a rolling window, and touches nothing else.
    """
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_scan_usage (
        program_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (program_id, target, window_start)
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bb_scan_usage_program "
        "ON bb_scan_usage (program_id, window_start)"
    )
    conn.commit()
    conn.close()
    logger.info("SECURITY TESTING DATABASE: OK")


def _check_and_use_scan_quota(program_id: int, target: str,
                              now: Optional[int] = None) -> Tuple[bool, str]:
    """Allow-then-increment, same shape as quota.check_and_use_quota().
    A blocked request never increments, so being rate limited does not
    make the next window worse. Returns (allowed, reason)."""
    now = now if now is not None else int(time.time())
    window = now - (now % RATE_LIMIT_WINDOW_SECONDS)

    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        program_used = conn.execute(
            "SELECT COALESCE(SUM(count), 0) AS n FROM bb_scan_usage "
            "WHERE program_id=? AND window_start=?",
            (program_id, window),
        ).fetchone()["n"]
        if program_used >= MAX_REQUESTS_PER_PROGRAM:
            conn.rollback()
            return False, "RATE_LIMIT_PROGRAM"

        row = conn.execute(
            "SELECT count FROM bb_scan_usage "
            "WHERE program_id=? AND target=? AND window_start=?",
            (program_id, target, window),
        ).fetchone()
        if row and row["count"] >= MAX_REQUESTS_PER_TARGET:
            conn.rollback()
            return False, "RATE_LIMIT_TARGET"

        conn.execute(
            "INSERT INTO bb_scan_usage (program_id, target, window_start, count) "
            "VALUES (?, ?, ?, 1) "
            "ON CONFLICT(program_id, target, window_start) DO UPDATE SET count = count + 1",
            (program_id, target, window),
        )
        conn.commit()
        return True, "OK"
    except sqlite3.Error:
        conn.rollback()
        logger.exception("SCAN QUOTA ERROR | program_id=%s", program_id)
        return False, "RATE_LIMIT_ERROR"   # fail closed
    finally:
        conn.close()


# ---------------- Network destination guard ----------------

def _forbidden_ip_reason(ip_text: str) -> Optional[str]:
    """None if this address may be connected to, else the reason it may
    not. Unconditional by design: this is not reachable from scope, and
    no Program, Authorization, or scope rule can switch it off.

    Anything unparseable is refused -- fail closed, never fail open.
    """
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return "DESTINATION_UNPARSEABLE"

    if ip.is_unspecified:
        return "DESTINATION_UNSPECIFIED"
    if ip.is_loopback:
        return "DESTINATION_LOOPBACK"
    if ip.is_link_local:
        # Covers 169.254.0.0/16, which is where the cloud metadata
        # endpoints (169.254.169.254, and GCP's metadata.google.internal)
        # live, and fe80::/10.
        return "DESTINATION_LINK_LOCAL"
    if ip.is_private:
        return "DESTINATION_PRIVATE"
    if ip.is_reserved:
        return "DESTINATION_RESERVED"
    if ip.is_multicast:
        return "DESTINATION_MULTICAST"
    if getattr(ip, "is_site_local", False):
        return "DESTINATION_SITE_LOCAL"

    # IPv4-mapped / 6to4 / Teredo let an attacker smuggle a v4 address
    # inside a v6 literal; unwrap and re-check rather than trust it.
    if ip.version == 6:
        mapped = getattr(ip, "ipv4_mapped", None) or getattr(ip, "sixtofour", None)
        if mapped is not None:
            return _forbidden_ip_reason(str(mapped))
        teredo = getattr(ip, "teredo", None)
        if teredo:
            return _forbidden_ip_reason(str(teredo[1]))
    return None
    
    
def _resolve_host(host: str, port: int) -> List[str]:
    """Blocking DNS resolution, kept separate so callers can push it onto
    a thread. Returns every A/AAAA address the resolver offers."""
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    seen, addresses = set(), []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            addresses.append(addr)
    return addresses
    
    
async def resolve_and_validate(host: str, port: int) -> Tuple[List[str], Optional[str]]:
    """Resolves `host` and refuses it unless EVERY address is allowed.

    Rejecting on *any* forbidden address rather than requiring all of
    them to be forbidden is deliberate: a host that answers with one
    public and one private address is exactly the DNS-rebinding shape
    this is meant to stop.
    """
    try:
        address = await asyncio.wait_for(
            asyncio.to_thread(_resolve_host, host, port),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        return [], "DNS_TIMEOUT"
    except (socket.gaierror, OSError, UnicodeError):
        return [], "DNS_RESOLUTION_FAILED"
        
    if not address:
        return [], "DNS_NO_ADDRESS"
    for addr in addresses:
        reason = _forbidden_ip_reason(addr)
        if reason:
            return [], reason
    return addresses, None
    

# ---------------- Target derivation ----------------

def _endpoint_from_target(normalized) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Turns an allowed NormalizedTarget into the concrete endpoint to
    request, or an error reason. Refuses IP/CIDR targets and non-web
    ports here so no later code has to remember to."""
    if normalized.target_type not in SCANNABLE_TARGET_TYPES:
        return None, "TARGET_TYPE_NOT_SCANNABLE"
        
    if normalized.target_type == TargetType.DOMAIN.value:
        return {"scheme": "https", "host": normalized.domain,
                "port": 443, "path": "/"}, None
                
    scheme = (normalized.scheme or "https").lower()
    if scheme not in ALLOWED_SCHEMES:
        return None, "SCHEME_NOT_ALLOWED"
    port = normalized.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        return None, "PORT_NOT_ALLOWED"
    return {"scheme": scheme, "host": normalized.domain, "port": port,
            "path": normalized.path or "/"}, None
            

def _endpoint_url(endpoint: Dict[str, Any]) -> str:
    default = 443 if endpoint["scheme"] == "https" else 80
    netloc = endpoint["host"] if endpoint["port"] == default \
        else f"{endpoint['host']}:{endpoint['port']}"
    return f"{endpoint['scheme']}://{netloc}{endpoint['path']}"
    
    
async def _validate_destination(program_id: int, endpoint: Dict[str, Any],
                                original_host: str,
                                original_target_type: str) -> Optional[str]:
    """Full destination check, applied to the first request and again to
    every redirect hop. Three independent gates, all of which must pass:

      1. the network guard (loopback/private/link-local/metadata),
      2. the port allow-list,
      3. scope_policy -- the hop's own host must itself be in scope.

    Gate 3 is what keeps a redirect from walking off the authorized
    target: example.com redirecting to evil.test stops here, because
    evil.test was never authorized.

    The hop is re-checked in the *same shape the operator authorized*.
    scope_policy does not treat a DOMAIN rule as covering a URL target
    (verified against the real API), so asking the wrong way round would
    reject every hop of a perfectly in-scope domain program. A DOMAIN
    target therefore re-checks the hop host as a domain; a URL target
    re-checks the full hop URL, which keeps URL rules' path-prefix
    matching meaningful.
    """
    if endpoint["port"] not in ALLOWED_PORTS:
        return "PORT_NOT_ALLOWED"
    if endpoint["scheme"] not in ALLOWED_SCHEMES:
        return "SCHEME_NOT_ALLOWED"
        
    if endpoint["host"] != original_host:
        probe = (endpoint["host"] if original_target_type == TargetType.DOMAIN.value
                  else _endpoint_url(endpoint))
        hop_decision = evaluate_target(program_id, probe)
        if not hop_decision.allowed:
            return f"REDIRECT_OUT_OF_SCOPE:{hop_decision.reason}"
            
    _addresses, reason = await resolve_and_validate(endpoint["host"], endpoint["port"])
    return reason


# ---------------- HTTP primitive ----------------

@dataclass
class HttpResponse:
    status_code: int
    headers: Dict[str, str]
    set_cookies: List[str]
    body_preview: str
    url: str
    truncated: bool = False


async def _fetch_once(endpoint: Dict[str, Any]) -> Tuple[Optional[HttpResponse], Optional[str]]:
    """Exactly one HTTP request. Redirects are never auto-followed --
    the caller re-validates each hop instead. The body is read as a
    stream and abandoned at MAX_RESPONSE_BYTES so a hostile or merely
    enormous response cannot exhaust memory."""
    if not _HTTPX_AVAILABLE:
        return None, "HTTP_CLIENT_UNAVAILABLE"

    url = _endpoint_url(endpoint)
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
            max_redirects=0,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        ) as client:
            async with client.stream("GET", url) as response:
                chunks, total, truncated = [], 0, False
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        chunks.append(chunk[: max(0, MAX_RESPONSE_BYTES - (total - len(chunk)))])
                        truncated = True
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks)[:MAX_RESPONSE_BYTES]

                headers = {k.lower(): v for k, v in response.headers.items()}
                set_cookies = [
                    v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"
                ]
                return HttpResponse(
                    status_code=response.status_code,
                    headers=headers,
                    set_cookies=set_cookies,
                    body_preview=raw.decode("utf-8", errors="replace")[:4000],
                    url=url,
                    truncated=truncated,
                ), None
    except asyncio.TimeoutError:
        return None, "REQUEST_TIMEOUT"
    except Exception as exc:  # httpx.HTTPError and anything below it
        # Never surface the exception text: it can carry the resolved
        # host, local paths, or proxy details.
        logger.info("SECURITY CHECK HTTP ERROR | %s", type(exc).__name__)
        return None, "REQUEST_FAILED"
        
        
async def _fetch_chain(program_id: int, endpoint: Dict[str, Any],
                       original_host: str,
                       original_target_type: str) -> Tuple[List[HttpResponse], Optional[str]]:
    """Follows redirects manually, re-validating every hop, up to
    MAX_REDIRECTS. Returns the chain of responses actually fetched."""
    chain: List[HttpResponse] = []
    current = dict(endpoint)
    
    for _hop in range(MAX_REDIRECTS +1):
        response, error = await _fetch_once(current)
        if error:
            return chain, error
        chain.append(response)
        
        location = response.headers.get("location")
        if not (300 <= response.status_code < 400 and location):
            return chain, None
            
        next_endpoint, parse_error = _next_endpoint(current, location)
        if parse_error:
            return chain, parse_error
        reason = await _validate_destination(program_id, next_endpoint, original_host,
                                               original_target_type)
        if reason:
            return chain, reason
        current = next_endpoint
        
    return chain, "TOO_MANY_REDIRECTS"
    
    
def _next_endpoint(current: Dict[str, Any], location: str):
    """Resolves a Location header against the current endpoint."""
    from urllib.parse import urlsplit
    try:
        absolute = urljoin(_endpoint_url(current), location)
        parts = urlsplit(absolute)
    except ValueError:
        return None, "REDIRECT_UNPARSEABLE"
        
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return None, "SCHEME_NOT_ALLOWED"
    try:
        host, port = parts.hostname, parts.port
    except ValueError:
        return None, "REDIRECT_UNPARSEABLE"
    if not host:
        return None, "REDIRECT_UNPARSEABLE"

    normalized = normalize_target(f"{scheme}://{host}")
    if normalized is None or not normalized.domain:
        return None, "REDIRECT_UNPARSEABLE"

    return {"scheme": scheme, "host": normalized.domain,
            "port": port or (443 if scheme == "https" else 80),
            "path": parts.path or "/"}, None


# ---------------- TLS primitive ----------------

def _tls_peek(host: str, ip: str, port: int) -> Dict[str, Any]:
    """Blocking TLS handshake against a pre-validated IP, with SNI set to
    the hostname so the right certificate comes back and validation still
    applies. Connecting to the IP we already checked -- rather than
    re-resolving the name -- is what closes the rebinding window for this
    check. Reads metadata only; sends no application data."""
    context = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=TLS_TIMEOUT_SECONDS) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
        cert = tls_sock.getpeercert() or {}
        return {
                "tls_version": tls_sock.version(),
                "cipher": (tls_sock.cipher() or (None,))[0],
                "subject": _flatten_name(cert.get("subject")),
                "issuer": _flatten_name(cert.get("issuer")),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "san_count": len(cert.get("subjectAltName", ())),
            }
            
            
def _flatten_name(name) -> Dict[str, str]:
    flat = {}
    for rdn in (name or ()):
        for key, value in rdn:
            flat[key] = value
    return flat
    

# ---------------- Checks (each reads one already-fetched response) ----------------

async def _check_headers(ctx) -> CheckResult:
    chain, error = await _fetch_chain(ctx["program_id"], ctx["endpoint"], ctx["host"],
                                     ctx["target_type"])
    if error and not chain:
        return _failed(error, **ctx["ids"])
    response = chain[-1]
    
    observations = []
    for header in _SECURITY_HEADERS:
        if header not in response.headers:
            observations.append(
                Observation("INFO", "VERSION_DISCLOSURE",
                            f"{header}: {response.headers[header][:100]}"))
                            
    result = CheckResult(ok=True, status="COMPLETED", **ctx["ids"])
    result.observations = observations
    result.data = {
        "status_code": response.status_code,
        "present_security_headers": [h for h in _SECURITY_HEADERS if h in response.headers],
        "redirect_hops": len(chain) - 1,
    }
    return result
    
    
async def _check_cookies(ctx) -> CheckResult:
    chain, error = await _fetch_chain(ctx["program_id"], ctx["endpoint"], ctx["host"],
                                     ctx["target_type"])
    if error and not chain:
        return _failed(error, **ctx["ids"])
    response = chain[-1]
    
    observations = []
    for raw_cookie in response.set_cookies:
        name = raw_cookie.split("=", 1)[0].strip()
        lowered = raw_cookie.lower()
        if "secure" not in lowered:
            observations.append(Observation("MEDIUM", "COOKIE_MISSING_SECURE", name))
        if "httponly" not in lowered:
            observations.append(Observation("MEDIUM", "COOKIE_MISSING_HTTPONLY", name))
        if "samesite" not in lowered:
            observations.append(Observation("LOW", "COOKIE_MISSING_SAMESITE", name))
            
    result = CheckResult(ok=True, status="COMPLETED", **ctx["ids"])
    result.observations = observations
    result.data = {"cookie_count": len(response.set_cookies),
                   "status_code": response.status_code}
    return result
    
    
async def _check_cors(ctx) -> CheckResult:
    chain, error = await _fetch_chain(ctx["program_id"], ctx["endpoint"], ctx["host"],
                                     ctx["target_type"])
    if error and not chain:
        return _failed(error, **ctx["ids"])
    response = chain[-1]

    allow_origin = response.headers.get("access-control-allow-origin")
    allow_credentials = (response.headers.get("access-control-allow-credentials", "")
                         .strip().lower() == "true")

    observations = []
    if allow_origin == "*" and allow_credentials:
        observations.append(Observation(
            "MEDIUM", "CORS_WILDCARD_WITH_CREDENTIALS",
            "Access-Control-Allow-Origin: * together with credentials"))
    elif allow_origin == "*":
        observations.append(Observation("INFO", "CORS_WILDCARD_ORIGIN", "*"))
    if allow_origin and allow_origin.strip().lower() == "null":
        observations.append(Observation("LOW", "CORS_NULL_ORIGIN", "null origin reflected"))

    result = CheckResult(ok=True, status="COMPLETED", **ctx["ids"])
    result.observations = observations
    result.data = {"allow_origin": allow_origin,
                   "allow_credentials": allow_credentials}
    return result
    
    
async def _check_redirects(ctx) -> CheckResult:
    chain, error = await _fetch_chain(ctx["program_id"], ctx["endpoint"], ctx["host"],
                                     ctx["target_type"])
    if error and not chain:
        return _failed(error, **ctx["ids"])

    observations = []
    if error:
        observations.append(Observation("INFO", "REDIRECT_CHAIN_STOPPED", error))
    if ctx["endpoint"]["scheme"] == "http":
        final = chain[-1]
        upgraded = final.url.startswith("https://")
        if not upgraded:
            observations.append(Observation("MEDIUM", "NO_HTTPS_REDIRECT",
                                            "plain HTTP is served without upgrading"))

    result = CheckResult(ok=True, status="COMPLETED", **ctx["ids"])
    result.observations = observations
    result.data = {
        "hops": [{"url": r.url, "status_code": r.status_code,
                  "location": r.headers.get("location")} for r in chain],
        "hop_count": len(chain) - 1,
    }
    return result
    
    
async def _check_technology(ctx) -> CheckResult:
    """Passive only: reads software hints out of the response already
    fetched. Never requests /wp-admin, /.git, or any other probe path --
    that would be content discovery, which Phase 8 forbids."""
    chain, error = await _fetch_chain(ctx["program_id"], ctx["endpoint"], ctx["host"],
                                     ctx["target_type"])
    if error and not chain:
        return _failed(error, **ctx["ids"])
    response = chain[-1]

    signals, observations = {}, []
    for header in _VERSION_DISCLOSING_HEADERS:
        if header in response.headers:
            signals[header] = response.headers[header][:100]
            observations.append(Observation("INFO", "TECHNOLOGY_HEADER",
                                            f"{header}: {signals[header]}"))
    generator = response.headers.get("x-generator")
    if generator:
        signals["generator"] = generator[:100]

    result = CheckResult(ok=True, status="COMPLETED", **ctx["ids"])
    result.observations = observations
    result.data = {"signals": signals, "status_code": response.status_code}
    return result
    
    
async def _check_tls(ctx) -> CheckResult:
    endpoint = ctx["endpoint"]
    if endpoint["scheme"] != "https":
        return _failed("TLS_REQUIRES_HTTPS", **ctx["ids"])

    addresses = ctx["addresses"]
    if not addresses:
        return _failed("DNS_NO_ADDRESS", **ctx["ids"])

    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(_tls_peek, endpoint["host"], addresses[0], endpoint["port"]),
            timeout=TLS_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        return _failed("TLS_TIMEOUT", **ctx["ids"])
    except ssl.SSLCertVerificationError:
        return _failed("TLS_CERTIFICATE_INVALID", **ctx["ids"])
    except (ssl.SSLError, OSError) as exc:
        logger.info("SECURITY CHECK TLS ERROR | %s", type(exc).__name__)
        return _failed("TLS_HANDSHAKE_FAILED", **ctx["ids"])

    observations = []
    not_after = info.get("not_after")
    if not_after:
        try:
            expires_at = ssl.cert_time_to_seconds(not_after)
            days_left = int((expires_at - time.time()) // 86400)
            info["days_until_expiry"] = days_left
            if days_left < 0:
                observations.append(Observation("MEDIUM", "TLS_CERT_EXPIRED",
                                                f"expired {abs(days_left)} days ago"))
            elif days_left < 30:
                observations.append(Observation("LOW", "TLS_CERT_EXPIRING_SOON",
                                                f"{days_left} days remaining"))
        except (ValueError, TypeError):
            pass
    version = info.get("tls_version") or ""
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        observations.append(Observation("MEDIUM", "TLS_OBSOLETE_VERSION", version))

    result = CheckResult(ok=True, status="COMPLETED", **ctx["ids"])
    result.observations = observations
    result.data = info
    return result
    
    
# Fixed allow-list. check_type is looked up here and nowhere else; a
# value that is not a key never reaches any code path, so an arbitrary
# string, shell command, URL, or Python expression cannot be executed.
CHECK_TYPES = {
    "headers": _check_headers,
    "tls": _check_tls,
    "cookies": _check_cookies,
    "redirects": _check_redirects,
    "cors": _check_cors,
    "technology": _check_technology,
}
VALID_CHECK_TYPES = frozenset(CHECK_TYPES)


# ---------------- Orchestration ----------------

async def run_security_check(program_id: int, target: str, check_type: str,
                             actor: int) -> Dict[str, Any]:
    """The single entry point. Fail-closed at every step.

    Nothing active happens until evaluate_target() has explicitly
    allowed the target: no DNS lookup, no TCP connection, no TLS
    handshake, no HTTP request. There is no `is_admin` parameter, so
    chat-admin status cannot influence the outcome.
    """
    ids = {"program_id": program_id if isinstance(program_id, int) else None,
           "target": None, "check_type": None}

    # --- input validation, before anything else ---
    if not isinstance(program_id, int) or isinstance(program_id, bool) or program_id <= 0:
        return _denied("INVALID_PROGRAM_ID", **ids).as_dict()
    if not isinstance(actor, int) or isinstance(actor, bool) or actor <= 0:
        return _denied("INVALID_ACTOR", **ids).as_dict()
    if not isinstance(check_type, str) or check_type not in CHECK_TYPES:
        return _denied("UNKNOWN_CHECK", **ids).as_dict()
    ids["check_type"] = check_type
    if not isinstance(target, str) or not target.strip():
        return _denied("TARGET_INVALID", **ids).as_dict()

    program = get_program(program_id)
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, actor, actor="user", action="SECURITY_CHECK_REQUESTED",
                    detail=f"program_id={program_id} check_type={check_type}")

    def deny(reason: str) -> Dict[str, Any]:
        write_audit_log(chat_id, actor, actor="system", action="SECURITY_CHECK_DENIED",
                        detail=f"program_id={program_id} check_type={check_type} "
                               f"target={ids['target']} reason={reason}")
        return _denied(reason, **ids).as_dict()

    try:
        # --- THE GATE. Nothing above this line touched the network. ---
        decision = evaluate_target(program_id, target)
        if not decision.allowed:
            return deny(decision.reason)

        normalized = normalize_target(target)
        if normalized is None:
            return deny("TARGET_INVALID")
        ids["target"] = normalized.raw if normalized.target_type == TargetType.URL.value \
            else (normalized.domain or normalized.raw)

        endpoint, endpoint_error = _endpoint_from_target(normalized)
        if endpoint_error:
            return deny(endpoint_error)

        allowed, rate_reason = _check_and_use_scan_quota(program_id, ids["target"])
        if not allowed:
            return deny(rate_reason)

        # --- first active operation: DNS, still gated ---
        addresses, dns_reason = await resolve_and_validate(endpoint["host"], endpoint["port"])
        if dns_reason:
            return deny(dns_reason)

        write_audit_log(chat_id, actor, actor="user", action="SECURITY_CHECK_STARTED",
                        detail=f"program_id={program_id} check_type={check_type} "
                               f"target={ids['target']}")

        ctx = {"program_id": program_id, "endpoint": endpoint, "host": endpoint["host"],
               "target_type": normalized.target_type, "addresses": addresses, "ids": ids}

        async with _concurrency:
            result = await CHECK_TYPES[check_type](ctx)

        action = "SECURITY_CHECK_COMPLETED" if result.ok else "SECURITY_CHECK_FAILED"
        write_audit_log(chat_id, actor, actor="system", action=action,
                        detail=f"program_id={program_id} check_type={check_type} "
                               f"target={ids['target']} status={result.status} "
                               f"observations={len(result.observations)}")
        return result.as_dict()

    except Exception:
        # Catch-all. Logged server-side with a traceback; the caller gets
        # a bare reason code so no stack trace, path, or hostname leaks
        # back into a Telegram message.
        logger.exception("SECURITY CHECK INTERNAL ERROR | program_id=%s", program_id)
        write_audit_log(chat_id, actor, actor="system", action="SECURITY_CHECK_FAILED",
                        detail=f"program_id={program_id} check_type={check_type} "
                               f"reason=INTERNAL_ERROR")
        return _failed("INTERNAL_ERROR", **ids).as_dict()


# ---------------- Presentation ----------------

_REASON_TH = {
    "UNKNOWN_CHECK": "ประเภทการตรวจไม่ถูกต้อง",
    "INVALID_PROGRAM_ID": "program_id ไม่ถูกต้อง",
    "INVALID_ACTOR": "ผู้ใช้ไม่ถูกต้อง",
    "TARGET_INVALID": "รูปแบบ target ไม่ถูกต้อง",
    "TARGET_TYPE_NOT_SCANNABLE": "สแกนได้เฉพาะ domain หรือ URL เท่านั้น (IP/CIDR ไม่อนุญาต)",
    "PORT_NOT_ALLOWED": "อนุญาตเฉพาะพอร์ต 80/443",
    "SCHEME_NOT_ALLOWED": "อนุญาตเฉพาะ http/https",
    "RATE_LIMIT_PROGRAM": "Program นี้ใช้โควตาการตรวจครบแล้ว รอรอบถัดไป",
    "RATE_LIMIT_TARGET": "target นี้ถูกตรวจบ่อยเกินไป รอรอบถัดไป",
    "RATE_LIMIT_ERROR": "ตรวจสอบโควตาไม่สำเร็จ (fail-closed: DENY)",
    "DESTINATION_LOOPBACK": "ปลายทางเป็น loopback — ไม่อนุญาตเด็ดขาด",
    "DESTINATION_PRIVATE": "ปลายทางเป็นเครือข่ายภายใน — ไม่อนุญาตเด็ดขาด",
    "DESTINATION_LINK_LOCAL": "ปลายทางเป็น link-local/metadata — ไม่อนุญาตเด็ดขาด",
    "DESTINATION_RESERVED": "ปลายทางเป็น reserved address — ไม่อนุญาต",
    "DESTINATION_MULTICAST": "ปลายทางเป็น multicast — ไม่อนุญาต",
    "DESTINATION_UNSPECIFIED": "ปลายทางไม่ระบุ — ไม่อนุญาต",
    "DESTINATION_UNPARSEABLE": "ที่อยู่ปลายทางอ่านไม่ออก (fail-closed: DENY)",
    "DNS_RESOLUTION_FAILED": "resolve DNS ไม่สำเร็จ",
    "DNS_TIMEOUT": "resolve DNS นานเกินไป",
    "DNS_NO_ADDRESS": "ไม่พบ IP ของโดเมนนี้",
    "REQUEST_TIMEOUT": "request หมดเวลา",
    "REQUEST_FAILED": "เชื่อมต่อปลายทางไม่สำเร็จ",
    "TOO_MANY_REDIRECTS": f"redirect เกิน {MAX_REDIRECTS} ครั้ง",
    "REDIRECT_UNPARSEABLE": "Location header อ่านไม่ออก",
    "TLS_REQUIRES_HTTPS": "การตรวจ TLS ต้องใช้ https",
    "TLS_TIMEOUT": "TLS handshake หมดเวลา",
    "TLS_HANDSHAKE_FAILED": "TLS handshake ไม่สำเร็จ",
    "TLS_CERTIFICATE_INVALID": "ใบรับรอง TLS ไม่ผ่านการตรวจสอบ",
    "HTTP_CLIENT_UNAVAILABLE": "ยังไม่ได้ติดตั้ง httpx บนเซิร์ฟเวอร์",
    "INTERNAL_ERROR": "เกิดข้อผิดพลาดภายใน (fail-closed)",
}


def deny_text(reason: str) -> str:
    if reason.startswith("REDIRECT_OUT_OF_SCOPE"):
        return "❌ redirect ออกไปนอก scope ที่ได้รับอนุญาต — หยุดการตรวจแล้ว"
    return "❌ " + _REASON_TH.get(reason, reason)
    
    
def format_check_result(result: Dict[str, Any]) -> str:
    """Renders a result dict for Telegram. Prints only fields this module
    produced -- never raw response bodies, environment values, or paths."""
    if not result.get("ok"):
        return deny_text(result.get("reason", "UNKNOWN"))

    lines = [
        f"🔎 ผลตรวจ [{result['check_type']}] {result['target']}",
        f"สถานะ: {result['status']}",
    ]
    data = result.get("data") or {}
    if "status_code" in data:
        lines.append(f"HTTP: {data['status_code']}")
    if result["check_type"] == "tls":
        for key in ("tls_version", "not_after", "days_until_expiry"):
            if data.get(key) is not None:
                lines.append(f"{key}: {data[key]}")

    observations = result.get("findings") or []
    if not observations:
        lines.append("\nไม่พบข้อสังเกต")
    else:
        lines.append(f"\nข้อสังเกต {len(observations)} รายการ:")
        for o in observations[:25]:
            detail = f" — {o['detail']}" if o["detail"] else ""
            lines.append(f"• [{o['severity_hint']}] {o['code']}{detail}")
        if len(observations) > 25:
            lines.append(f"… และอีก {len(observations) - 25} รายการ")

    lines.append("\nℹ️ ผลนี้เป็นข้อสังเกตเท่านั้น ยังไม่ได้สร้าง Finding "
                 "ถ้าจะรายงานจริงให้ใช้ /bbfinding new")
    return "\n".join(lines)