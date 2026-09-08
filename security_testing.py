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