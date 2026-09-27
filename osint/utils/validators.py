"""
osint.utils.validators — normalize and validate the target identifiers the
OSINT sources accept. Standard library only (ipaddress, re, unicodedata).

Being strict here is a safety property, not just tidiness: a source module
trusts that the string it received is a real domain / IP / ASN, so these
functions reject junk (and obvious SSRF footguns like embedded credentials or
non-global IPs) before any network call is built from user input.
"""

import re
import ipaddress
import unicodedata
from typing import Optional

# A conservative hostname/domain matcher: labels of alphanumerics and hyphens,
# 1..63 chars each, at least two labels, a non-numeric TLD of 2+ chars.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)
_ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.IGNORECASE)


def normalize_domain(raw: Optional[str]) -> Optional[str]:
    """Lower-case, strip a scheme/path/port/leading '*.'/trailing dot, and
    IDNA-encode unicode. Returns a bare registrable-ish hostname or None."""
    if not raw:
        return None
    text = unicodedata.normalize("NFKC", raw).strip().lower()
    if not text:
        return None
    # Drop a scheme and anything after the authority.
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    # Reject embedded credentials (user:pass@host) rather than silently taking
    # the host part — it usually signals a copied URL or an injection attempt.
    if "@" in text:
        return None
    text = text.split(":", 1)[0]           # strip :port
    text = text.rstrip(".")                # strip fully-qualified trailing dot
    if text.startswith("*."):
        text = text[2:]
    if not text:
        return None
    try:
        text = text.encode("idna").decode("ascii")   # unicode -> punycode
    except Exception:
        pass
    return text if _DOMAIN_RE.match(text) else None


def is_valid_domain(raw: Optional[str]) -> bool:
    return normalize_domain(raw) is not None


def normalize_ip(raw: Optional[str]) -> Optional[str]:
    """Return the compressed string form of a valid IPv4/IPv6 address, or None."""
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def is_valid_ip(raw: Optional[str]) -> bool:
    return normalize_ip(raw) is not None


def is_public_ip(raw: Optional[str]) -> bool:
    """True only for a globally routable address. Sources that resolve a target
    to an IP should refuse private/loopback/link-local/reserved space to avoid
    turning the framework into an SSRF probe of internal networks."""
    ip_str = normalize_ip(raw)
    if ip_str is None:
        return False
    ip = ipaddress.ip_address(ip_str)
    return ip.is_global and not ip.is_multicast


def normalize_asn(raw: Optional[str]) -> Optional[int]:
    """'AS15169', 'as15169', '15169' -> 15169. Rejects out-of-range values."""
    if not raw:
        return None
    m = _ASN_RE.match(raw.strip())
    if not m:
        return None
    value = int(m.group(1))
    # 0 and 4294967295 are reserved; valid public ASNs sit between.
    return value if 0 < value < 4294967295 else None


def is_valid_asn(raw: Optional[str]) -> bool:
    return normalize_asn(raw) is not None
