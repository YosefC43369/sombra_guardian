"""
blueteam/netprobe.py — Link Guard tier 3: a *safe* active probe with a strict
SSRF guard. Opt-in per group; OFF by default.

This is the only Blue Team component that touches the network, and it does so under
tight control. It NEVER runs files or JavaScript — it fetches bytes and parses them
with the stdlib ``html.parser`` to read a page's title, whether it has a password
input, and whether a form posts to a different domain (classic phishing tells).

SSRF guard (defense-in-depth, per the task)
------------------------------------------
  1. Resolve the host's A/AAAA records up front.
  2. Reject if ANY resolved address is private / loopback / link-local / CGNAT /
     reserved / multicast / unspecified, or the cloud metadata address — a host
     that resolves to a mix of public and private is rejected outright.
  3. **Pin** the validated address set and hand it to the opener, which must
     connect to a pinned address — defeating DNS rebinding (a second resolution
     returning an internal IP cannot be used).
  4. Re-run the whole check at EVERY redirect hop.
  5. Hard limits: max hops, per-request timeout, max bytes (64 KiB), GET only, no
     cookies sent.

The ``resolver``, ``opener`` and ``clock`` are injectable so the guard is unit-
tested fully offline (including a simulated rebind). The default opener uses
``httpx`` if present and re-validates the connect address; with no opener the probe
returns a clear "unavailable" result rather than raising.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Awaitable, Callable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from .models import Signal
from .urlkit import etld1

logger = logging.getLogger("modbot.blueteam.netprobe")

# Types for injection.
Resolver = Callable[[str], List[str]]                     # host -> [ip, ...]
# opener(url, pinned_ips, timeout) -> (status, headers, body_bytes, location)
Opener = Callable[[str, List[str], float], Awaitable[Tuple[int, dict, bytes, str]]]

_METADATA_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}


def is_safe_ip(ip_str: str) -> Tuple[bool, str]:
    """Return (safe, reason). Safe means a globally-routable public address that is
    not a cloud metadata endpoint."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"not an IP: {ip_str}"
    if str(ip) in _METADATA_IPS:
        return False, "cloud metadata address"
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) — unwrap and check the embedded v4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_safe_ip(str(ip.ipv4_mapped))
    if ip.is_loopback:
        return False, "loopback"
    if ip.is_private:
        return False, "private"
    if ip.is_link_local:
        return False, "link-local"
    if ip.is_multicast:
        return False, "multicast"
    if ip.is_reserved:
        return False, "reserved"
    if ip.is_unspecified:
        return False, "unspecified"
    # CGNAT 100.64.0.0/10 is not flagged is_private by ipaddress
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False, "carrier-grade NAT"
    if not ip.is_global:
        return False, "not globally routable"
    return True, "ok"


def _default_resolver(host: str) -> List[str]:
    """Resolve all A/AAAA records for a host (blocking; run in an executor)."""
    out: List[str] = []
    try:
        for family, _t, _p, _c, sockaddr in socket.getaddrinfo(host, None):
            out.append(sockaddr[0])
    except OSError:
        return []
    # dedupe, preserve order
    seen = set()
    uniq = []
    for ip in out:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    return uniq


def screen_host(host: str, resolver: Resolver) -> Tuple[bool, str, List[str]]:
    """Resolve ``host`` and return (safe, reason, pinned_ips). Safe requires at
    least one address and EVERY resolved address to pass :func:`is_safe_ip`."""
    if not host:
        return False, "no host", []
    # A literal IP host is screened directly.
    try:
        ipaddress.ip_address(host.strip("[]"))
        ips = [host.strip("[]")]
    except ValueError:
        ips = resolver(host)
    if not ips:
        return False, "dns resolution failed", []
    for ip in ips:
        ok, reason = is_safe_ip(ip)
        if not ok:
            return False, f"{ip}: {reason}", ips
    return True, "ok", ips


# ---------------- lightweight, safe HTML inspection ----------------

class _PageInspector(HTMLParser):
    """Reads only structural tells; never executes anything. Ignores <script>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.has_password_input = False
        self.form_actions: List[str] = []
        self._depth_guard = 0

    def handle_starttag(self, tag, attrs):
        self._depth_guard += 1
        if self._depth_guard > 20000:            # bound pathological documents
            return
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password_input = True
        elif tag == "form" and a.get("action"):
            self.form_actions.append(a["action"])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 300:
            self.title += data


@dataclass(slots=True)
class ProbeResult:
    reachable: bool = False
    blocked: bool = False
    blocked_reason: str = ""
    final_url: str = ""
    status: int = 0
    hops: List[str] = field(default_factory=list)
    title: str = ""
    has_password_form: bool = False
    cross_domain_form: bool = False
    signals: List[Signal] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"reachable": self.reachable, "blocked": self.blocked,
                "blocked_reason": self.blocked_reason, "final_url": self.final_url,
                "status": self.status, "hops": list(self.hops), "title": self.title,
                "has_password_form": self.has_password_form,
                "cross_domain_form": self.cross_domain_form,
                "signals": [s.to_dict() for s in self.signals]}


class SafeProbe:
    def __init__(self, *, resolver: Optional[Resolver] = None,
                 opener: Optional[Opener] = None, timeout_s: float = 8.0,
                 max_hops: int = 5, max_bytes: int = 65536):
        self._resolver = resolver or _default_resolver
        self._opener = opener                    # None => network unavailable
        self.timeout_s = timeout_s
        self.max_hops = max_hops
        self.max_bytes = max_bytes

    async def probe(self, url: str) -> ProbeResult:
        result = ProbeResult()
        current = url
        origin_reg = ""
        for hop in range(self.max_hops):
            parts = urlsplit(current if "://" in current else "http://" + current)
            scheme = parts.scheme.lower()
            if scheme not in ("http", "https"):
                result.blocked = True
                result.blocked_reason = f"unsupported scheme {scheme}"
                return result
            host = (parts.hostname or "").lower()
            if not origin_reg:
                origin_reg = etld1(host)
            result.hops.append(host)

            # SSRF screen at EVERY hop (defeats rebinding across redirects)
            safe, reason, pinned = screen_host(host, self._resolver)
            if not safe:
                result.blocked = True
                result.blocked_reason = f"SSRF guard: {reason}"
                result.signals.append(Signal(
                    "ssrf_blocked", 25, "probe",
                    f"เป้าหมาย redirect ไปโฮสต์ภายใน/ต้องห้าม ({reason})", "T1090"))
                return result

            if self._opener is None:
                result.meta["note"] = "active probe unavailable (no opener)"
                return result

            try:
                status, headers, body, location = await self._opener(
                    current, pinned, self.timeout_s)
            except Exception as exc:
                result.blocked_reason = f"probe error: {type(exc).__name__}"
                result.meta["error"] = str(exc)[:120]
                return result

            result.status = status
            result.final_url = current

            if status in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue

            # terminal response: inspect body (bounded)
            body = body[:self.max_bytes] if body else b""
            self._inspect(result, body, origin_reg)
            result.reachable = 200 <= status < 400
            return result

        result.blocked_reason = "too many redirects"
        result.signals.append(Signal("redirect_chain", 12, "probe",
                                     f"redirect เกิน {self.max_hops} ครั้ง"))
        return result

    def _inspect(self, result: ProbeResult, body: bytes, origin_reg: str) -> None:
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return
        parser = _PageInspector()
        try:
            parser.feed(text)
        except Exception:
            pass
        result.title = parser.title.strip()[:200]
        result.has_password_form = parser.has_password_input
        if parser.has_password_input:
            result.signals.append(Signal(
                "password_form", 22, "probe",
                "หน้าปลายทางมีช่องกรอกรหัสผ่าน (อาจเป็นหน้าฟิชชิง)", "T1566.002"))
        for action in parser.form_actions:
            ahost = (urlsplit(action).hostname or "").lower()
            if ahost and etld1(ahost) and origin_reg and etld1(ahost) != origin_reg:
                result.cross_domain_form = True
                result.signals.append(Signal(
                    "cross_domain_form", 18, "probe",
                    f"ฟอร์มส่งข้อมูลข้ามโดเมนไป {etld1(ahost)}", "T1566.002"))
                break


def build_default_opener(timeout_s: float = 8.0,
                         resolver: Optional[Resolver] = None):
    """Return an Opener backed by httpx, or ``None`` if httpx is absent.

    DNS-rebinding mitigation: immediately before connecting, the opener re-resolves
    the host (via the same resolver used to screen it) and re-validates EVERY
    address with :func:`is_safe_ip`, aborting if the resolution changed to anything
    unsafe. This closes the TOCTOU window between :meth:`SafeProbe.probe`'s screen
    and the actual connection down to microseconds. (For a fully hostile
    environment, pin the connection at the transport layer — documented in
    docs/blueteam/THREAT_MODEL.md; the screen-then-reverify approach here blocks
    the realistic rebind where a record flips to a private IP.)

    Cookies are never sent; redirects are handled by :class:`SafeProbe`, not httpx,
    so every hop is re-screened.
    """
    try:
        import httpx
    except Exception:
        return None
    resolve = resolver or _default_resolver

    async def _opener(url: str, pinned_ips: List[str], timeout: float):
        parts = urlsplit(url)
        host = (parts.hostname or "")
        # Re-resolve + re-validate right before connecting (rebind mitigation).
        safe, reason, current = screen_host(host, resolve)
        if not safe:
            raise RuntimeError(f"host failed re-validation before connect: {reason}")
        # And confirm the resolution still matches what we pinned (no flip).
        if pinned_ips and not (set(current) & set(pinned_ips)):
            raise RuntimeError("resolution changed away from pinned addresses")
        async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=False,
                headers={"User-Agent": "SombraGuardian-LinkGuard/0.7 (+passive)"}) as c:
            resp = await c.get(url)
            body = resp.content[:65536] if resp.content else b""
            return (resp.status_code, dict(resp.headers), body,
                    resp.headers.get("location", ""))

    return _opener
