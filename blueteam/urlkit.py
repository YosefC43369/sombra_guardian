"""
blueteam/urlkit.py — URL extraction, de-obfuscation, canonicalization, defang and
eTLD+1, dependency-free.

This is the passive parsing core of Link Guard. It NEVER fetches anything — it
only reads text. Responsibilities:

  * **Extraction** from message text *and* Telegram entities (``url`` and, most
    importantly, ``text_link`` where the shown text is one domain but the href is
    another — a classic phish). Entities are passed as plain dicts so this is
    testable without python-telegram-bot.
  * **De-obfuscation (refang)** of the tricks scammers use: ``hxxp``, ``[.]``,
    ``(dot)``, spaces around dots, zero-width characters, ``@``-host tricks.
  * **Deterministic canonicalization** + a SHA-256 key for dedupe/cache.
  * **eTLD+1** via a compact built-in public-suffix table with a safe
    last-two-labels fallback (no external PSL dependency, per the task).
  * **Defang for output** (``hxxps://example[.]com``) so an admin reading the
    bot's reply cannot fat-finger a live malicious link (กติกาข้อ 7).
  * IP literal decoding (decimal/hex/octal/IPv6) and scheme classification
    (``data:``/``javascript:``/``tg://`` flagged, never executed).

Everything is plain text analysis; nothing here is an attack tool.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

__all__ = ["ExtractedURL", "extract_urls", "refang", "defang", "canonicalize",
           "etld1", "registrable_domain", "decode_ip_host", "host_scripts"]

_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿᠎]")

# Obfuscation → real-character map applied before parsing (refang).
_REFANG_REPLACEMENTS = [
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
    ("{dot}", "."), (" dot ", "."), ("[:]", ":"), ("(:)", ":"),
    ("[//]", "//"), ("hxxp", "http"), ("hXXp", "http"), ("hxtp", "http"),
    ("meow://", "http://"),
]
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*:", re.IGNORECASE)
# A permissive URL-ish finder over refanged text. We validate/parse afterwards.
_URLISH_RE = re.compile(
    r"""(
        (?:(?:data|javascript|vbscript|file|blob):[^\s<>"']+) # dangerous schemes (no //)
        | (?:[a-z][a-z0-9+.\-]{0,15}://[^\s<>"']+)      # scheme://...
        | (?:\b(?:www|t)\.[^\s<>"']+)                  # www.  / t.me...
        | (?:\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)+/[^\s<>"']*) # host/path bare
        | (?:\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)+\b)        # bare host
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_DANGEROUS_SCHEMES = {"data", "javascript", "vbscript", "file", "blob"}
_TELEGRAM_SCHEMES = {"tg"}

# Compact public-suffix table: the common multi-label suffixes we want eTLD+1 to
# get right (Thai + a handful of global ones). NOT the full PSL — a documented
# fallback (task: "คำนวณ eTLD+1 เองแบบมี fallback ไม่พึ่ง dependency"). Anything
# not listed falls back to the last two labels, which is correct for the vast
# majority of gTLDs (.com/.net/.io/.xyz/...).
_MULTI_SUFFIXES = frozenset([
    "co.th", "ac.th", "go.th", "or.th", "in.th", "net.th", "mi.th",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "edu.sg", "gov.sg", "com.my", "gov.my",
    "com.br", "com.tr", "co.in", "co.id", "co.kr", "co.za",
    "com.vn", "com.ph", "com.hk", "com.tw",
])


@dataclass(slots=True)
class ExtractedURL:
    raw: str                          # as it appeared (refanged form used to parse)
    url: str = ""                     # canonical URL
    scheme: str = ""
    host: str = ""                    # display/unicode host (lowercased)
    ascii_host: str = ""             # punycode/IDNA-encoded host
    host_type: str = "domain"        # domain | ipv4 | ipv6 | punycode | invalid
    port: Optional[int] = None
    path: str = ""
    etld1: str = ""
    display_text: str = ""           # for text_link: the shown text
    href_mismatch: bool = False      # shown text host != actual href host
    obfuscations: List[str] = field(default_factory=list)
    source: str = "text"             # text | entity_url | entity_text_link
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return hashlib.sha256((self.url or self.raw).encode("utf-8")).hexdigest()

    @property
    def is_dangerous_scheme(self) -> bool:
        return self.scheme in _DANGEROUS_SCHEMES

    @property
    def is_telegram(self) -> bool:
        return self.scheme in _TELEGRAM_SCHEMES or self.host in ("t.me", "telegram.me", "telegram.dog")

    def defanged(self) -> str:
        return defang(self.url or self.raw)

    def to_dict(self) -> Dict[str, Any]:
        return {"url": self.url, "defanged": self.defanged(), "scheme": self.scheme,
                "host": self.host, "ascii_host": self.ascii_host,
                "host_type": self.host_type, "etld1": self.etld1,
                "href_mismatch": self.href_mismatch,
                "obfuscations": list(self.obfuscations), "source": self.source,
                "key": self.key}


# ---------------- refang / defang ----------------

def refang(text: str) -> Tuple[str, List[str]]:
    """Undo common URL obfuscation. Returns (refanged_text, obfuscations_seen)."""
    seen: List[str] = []
    if not text:
        return "", seen
    original = text
    t = _ZERO_WIDTH_RE.sub("", text)
    if t != text:
        seen.append("zero_width")
    low = t.lower()
    for needle, repl in _REFANG_REPLACEMENTS:
        if needle.lower() in low:
            # case-insensitive replace
            t = re.sub(re.escape(needle), repl, t, flags=re.IGNORECASE)
            low = t.lower()
            seen.append(f"obfuscation:{needle}")
    # spaces around dots: "example . com" -> "example.com" (only between word chars)
    spaced = re.sub(r"(?<=\w)\s+\.\s+(?=\w)", ".", t)
    if spaced != t:
        seen.append("spaced_dots")
        t = spaced
    if t != original:
        seen.append("refanged")
    return t, seen


def defang(url: str) -> str:
    """Render a URL harmless for display: http->hxxp and . -> [.] in the host."""
    if not url:
        return ""
    out = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # defang dots in the authority portion only (keep path readable)
    try:
        parts = urlsplit(out if "://" in out else "hxxp://" + out)
        netloc = parts.netloc.replace(".", "[.]")
        rebuilt = urlunsplit((parts.scheme, netloc, parts.path, parts.query,
                              parts.fragment))
        return rebuilt
    except Exception:
        return out.replace(".", "[.]")


# ---------------- host helpers ----------------

def decode_ip_host(host: str) -> Optional[str]:
    """Decode an integer/hex/octal/dotted IP literal to a normal address string.

    Catches decimal (``2130706433``), hex (``0x7f000001``), octal
    (``0177.0.0.1``) and dotted-quad forms used to hide an IP destination.
    Returns the canonical address string, or ``None`` if ``host`` is not an IP.
    """
    h = host.strip().strip("[]")
    # IPv6
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    # single integer (decimal or 0x…)
    try:
        if re.fullmatch(r"0x[0-9a-fA-F]+", h):
            return str(ipaddress.ip_address(int(h, 16)))
        if re.fullmatch(r"\d+", h) and int(h) <= 0xFFFFFFFF:
            return str(ipaddress.ip_address(int(h)))
    except (ValueError, ipaddress.AddressValueError):
        pass
    # dotted with octal/hex octets, e.g. 0177.0.0.1 or 0x7f.0.0.1
    if re.fullmatch(r"[0-9xXa-fA-F]+(\.[0-9xXa-fA-F]+){3}", h):
        try:
            octets = []
            for part in h.split("."):
                if part.lower().startswith("0x"):
                    octets.append(int(part, 16))
                elif part.startswith("0") and len(part) > 1:
                    octets.append(int(part, 8))
                else:
                    octets.append(int(part))
            if all(0 <= o <= 255 for o in octets):
                return ".".join(str(o) for o in octets)
        except ValueError:
            return None
    return None


def host_scripts(host: str) -> set:
    """The set of Unicode scripts present in ``host`` letters (for mixed-script
    detection — a domain mixing Latin + Cyrillic is a homograph red flag)."""
    scripts = set()
    for ch in host:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        first = name.split(" ")[0]
        if first in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW",
                     "ARABIC", "THAI", "CJK", "HANGUL", "HIRAGANA", "KATAKANA"):
            scripts.add(first)
        else:
            scripts.add("OTHER")
    return scripts


def etld1(host: str) -> str:
    """Return the effective TLD + 1 label (registrable domain) for ``host``.

    Uses the compact built-in multi-suffix table, else the last two labels.
    """
    host = (host or "").strip(".").lower()
    if not host or _looks_like_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        # suffix is 2 labels -> registrable is last 3
        return last_three if len(labels) >= 3 else host
    return last_two


def registrable_domain(host: str) -> str:
    return etld1(host)


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------- parsing one URL ----------------

def _parse_one(raw: str, source: str = "text") -> Optional[ExtractedURL]:
    raw = raw.strip().strip('.,;)]}>"\'')
    if not raw:
        return None
    refanged, obf = refang(raw)
    candidate = refanged.strip()
    if not _SCHEME_RE.match(candidate):
        # bare host or www. — assume http for parsing, remember it had no scheme
        candidate2 = "http://" + candidate
        implied_scheme = True
    else:
        candidate2 = candidate
        implied_scheme = False
    try:
        parts = urlsplit(candidate2)
    except ValueError:
        return ExtractedURL(raw=raw, host_type="invalid", obfuscations=obf,
                            source=source)
    scheme = parts.scheme.lower()

    eu = ExtractedURL(raw=raw, obfuscations=obf, source=source, scheme=scheme,
                      path=parts.path or "")

    if scheme in _DANGEROUS_SCHEMES:
        eu.host_type = "scheme"
        eu.url = candidate
        eu.meta["dangerous_scheme"] = scheme
        return eu

    # "@host" trick: userinfo present -> the real host is after '@'
    if "@" in parts.netloc:
        eu.obfuscations.append("userinfo_at_host")

    hostport = parts.netloc.rsplit("@", 1)[-1]
    if hostport.startswith("["):                 # IPv6 literal [::1]:80
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostport)
        host = m.group(1) if m else hostport
        port = int(m.group(2)) if m and m.group(2) else None
    else:
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s.isdigit() else None
    host = host.strip().lower()
    eu.port = port

    # IP literal (incl. obfuscated decimal/hex/octal)?
    decoded_ip = decode_ip_host(host)
    if decoded_ip is not None:
        eu.host = decoded_ip
        eu.ascii_host = decoded_ip
        try:
            ip = ipaddress.ip_address(decoded_ip)
            eu.host_type = "ipv6" if ip.version == 6 else "ipv4"
        except ValueError:
            eu.host_type = "ipv4"
        if decoded_ip != host:
            eu.obfuscations.append("ip_obfuscated")
        eu.meta["ip"] = decoded_ip
    else:
        eu.host = host
        # IDNA / punycode
        try:
            eu.ascii_host = host.encode("idna").decode("ascii") if host else ""
        except Exception:
            eu.ascii_host = host
        if eu.ascii_host.startswith("xn--") or ".xn--" in eu.ascii_host:
            eu.host_type = "punycode"
        else:
            eu.host_type = "domain"
        eu.etld1 = etld1(eu.ascii_host or host)

    # canonical URL (scheme dropped back to original if implied)
    canon_scheme = "" if implied_scheme and scheme == "http" else scheme
    eu.url = canonicalize(candidate2, drop_scheme=implied_scheme and scheme == "http")
    if implied_scheme:
        eu.scheme = "http"
    return eu


def canonicalize(url: str, drop_scheme: bool = False) -> str:
    """Deterministic canonical form: lowercase scheme+host, strip default ports,
    drop fragment, keep path/query. Used for the dedupe/cache key."""
    try:
        if "://" not in url:
            url = "http://" + url
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        try:
            host = host.encode("idna").decode("ascii") if host else host
        except Exception:
            pass
        port = parts.port
        if port and not ((scheme == "http" and port == 80) or
                         (scheme == "https" and port == 443)):
            netloc = f"{host}:{port}"
        else:
            netloc = host
        path = parts.path or "/"
        out = urlunsplit(((scheme if not drop_scheme else ""), netloc, path,
                          parts.query, ""))
        return out.lstrip("/") if drop_scheme else out
    except Exception:
        return url


# ---------------- extraction from text + entities ----------------

def extract_urls(text: str,
                 entities: Optional[List[Dict[str, Any]]] = None) -> List[ExtractedURL]:
    """Extract every URL from a message.

    ``entities`` is a list of dicts mirroring Telegram MessageEntity:
        {"type": "url"|"text_link", "offset": int, "length": int, "url": str?}
    For a ``text_link`` we compare the *shown* text against the real href and set
    ``href_mismatch`` when their registrable domains differ — the highest-value
    phishing signal, invisible to plain text scanning.

    De-duplicated by canonical key; the richest record (e.g. one that carries a
    text_link mismatch) wins.
    """
    found: Dict[str, ExtractedURL] = {}
    order: List[str] = []

    def _add(eu: Optional[ExtractedURL]) -> None:
        if eu is None:
            return
        k = eu.key
        existing = found.get(k)
        if existing is None:
            found[k] = eu
            order.append(k)
        else:
            # merge: prefer a record that carries mismatch / more obfuscations
            if eu.href_mismatch and not existing.href_mismatch:
                found[k] = eu
            else:
                for o in eu.obfuscations:
                    if o not in existing.obfuscations:
                        existing.obfuscations.append(o)

    text = text or ""

    # 1) entities first (authoritative offsets + text_link href)
    for ent in (entities or []):
        etype = ent.get("type")
        if etype not in ("url", "text_link"):
            continue
        offset = int(ent.get("offset", 0))
        length = int(ent.get("length", 0))
        shown = text[offset:offset + length] if length else ""
        if etype == "text_link":
            href = ent.get("url", "")
            eu = _parse_one(href, source="entity_text_link")
            if eu is not None:
                eu.display_text = shown
                shown_eu = _parse_one(shown, source="text")
                if shown_eu is not None and shown_eu.host_type in ("domain", "punycode", "ipv4", "ipv6"):
                    shown_reg = shown_eu.etld1 or shown_eu.host
                    href_reg = eu.etld1 or eu.host
                    if shown_reg and href_reg and shown_reg != href_reg:
                        eu.href_mismatch = True
                        eu.meta["shown_domain"] = shown_reg
                        eu.meta["href_domain"] = href_reg
                _add(eu)
        else:  # plain url entity
            _add(_parse_one(shown or ent.get("url", ""), source="entity_url"))

    # 2) scan the refanged text for anything the entities missed
    refanged, _ = refang(text)
    for m in _URLISH_RE.finditer(refanged):
        _add(_parse_one(m.group(1), source="text"))

    return [found[k] for k in order]
