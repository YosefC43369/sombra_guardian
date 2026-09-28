"""
threat_actor_intelligence.models.ioc — normalized indicators of compromise.

Publicly-reported IOCs, normalized to a deterministic canonical form so the same
indicator reported by two vendors deduplicates to one row. Supported types match
the spec: domain, url, ip, asn, file hashes (md5/sha1/sha256), email, certificate
fingerprint, mutex, registry path (metadata), and YARA/Sigma *rule references*
(metadata only — no rule bodies, no samples, no weaponization).

Canonicalization reuses the shared ``blueteam.urlkit`` URL canonicalizer when it
is importable (single source of truth across the codebase) and falls back to a
local pure-stdlib implementation otherwise, so this module imports and its tests
run with zero cross-package coupling required.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .evidence import EvidenceBundle, TLP

try:  # shared URL canonicalizer if the blueteam package is importable
    from blueteam import urlkit as _urlkit
    _HAVE_URLKIT = True
except Exception:  # pragma: no cover - keep package self-contained
    _urlkit = None
    _HAVE_URLKIT = False

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA512_RE = re.compile(r"^[0-9a-f]{128}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ASN_RE = re.compile(r"^as(\d+)$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](-?[a-z0-9_])*\.)+[a-z]{2,63}$")


class IOCType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    ASN = "asn"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    EMAIL = "email"
    CERT_FINGERPRINT = "cert_fingerprint"
    MUTEX = "mutex"
    REGISTRY = "registry"            # metadata only
    YARA_REF = "yara_ref"            # rule reference/name only
    SIGMA_REF = "sigma_ref"          # rule reference/name only
    FILENAME = "filename"
    USER_AGENT = "user_agent"

    @classmethod
    def coerce(cls, raw: Any) -> "IOCType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.DOMAIN


class CanonicalizeError(ValueError):
    pass


def _fang(v: str) -> str:
    """Undo common defanging (hxxp, [.], (dot), [at]) before canonicalizing."""
    v = v.strip()
    v = re.sub(r"^h[xX]{2}p", "http", v)
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = re.sub(r"\[?\(?\bdot\b\)?\]?", ".", v, flags=re.IGNORECASE)
    v = v.replace("[:]", ":").replace("[/]", "/")
    v = re.sub(r"\[?\(?\bat\b\)?\]?", "@", v, flags=re.IGNORECASE) if "@" not in v and " at " in v else v
    return v.strip()


def canonicalize(ioc_type: IOCType, value: str) -> str:
    """Deterministic canonical form per type. Raises ``CanonicalizeError`` when a
    value cannot be a valid indicator of the given type."""
    t = IOCType.coerce(ioc_type)
    v = _fang(value or "")
    if not v:
        raise CanonicalizeError("empty value")

    if t == IOCType.URL:
        if _HAVE_URLKIT:
            try:
                return _urlkit.canonicalize(v)
            except Exception:
                pass
        if not re.match(r"^[a-z]+://", v, re.IGNORECASE):
            v = "http://" + v
        return v.rstrip("/").lower() if "://" in v else v
    if t == IOCType.DOMAIN:
        host = v.lower().rstrip(".").split("/")[0].split("@")[-1].split(":")[0]
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass
        if not _DOMAIN_RE.match(host):
            raise CanonicalizeError(f"not a domain: {value!r}")
        return host
    if t == IOCType.IP:
        return str(ipaddress.ip_address(v))
    if t == IOCType.CIDR:
        return str(ipaddress.ip_network(v, strict=False))
    if t == IOCType.ASN:
        m = _ASN_RE.match(v) or re.match(r"^(\d+)$", v)
        if not m:
            raise CanonicalizeError(f"not an ASN: {value!r}")
        return f"AS{int(m.group(1))}"
    if t in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512):
        h = v.lower()
        rx = {IOCType.MD5: _MD5_RE, IOCType.SHA1: _SHA1_RE,
              IOCType.SHA256: _SHA256_RE, IOCType.SHA512: _SHA512_RE}[t]
        if not rx.match(h):
            raise CanonicalizeError(f"invalid {t.value}: {value!r}")
        return h
    if t == IOCType.EMAIL:
        e = v.lower()
        if not _EMAIL_RE.match(e):
            raise CanonicalizeError(f"invalid email: {value!r}")
        return e
    if t == IOCType.CERT_FINGERPRINT:
        f = re.sub(r"[^0-9a-fA-F]", "", v).lower()
        if len(f) not in (40, 64):
            raise CanonicalizeError(f"invalid cert fingerprint: {value!r}")
        return f
    if t in (IOCType.MUTEX, IOCType.REGISTRY, IOCType.YARA_REF,
             IOCType.SIGMA_REF, IOCType.FILENAME, IOCType.USER_AGENT):
        return v.strip()
    return v


def detect_type(value: str) -> Optional[IOCType]:
    """Best-effort inference for a raw indicator string."""
    v = _fang(value or "")
    if not v:
        return None
    low = v.lower()
    if _SHA512_RE.match(low):
        return IOCType.SHA512
    if _SHA256_RE.match(low):
        return IOCType.SHA256
    if _SHA1_RE.match(low):
        return IOCType.SHA1
    if _MD5_RE.match(low):
        return IOCType.MD5
    if _ASN_RE.match(low):
        return IOCType.ASN
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            if not low.startswith(("http://", "https://")):
                return IOCType.CIDR
        except ValueError:
            pass
    try:
        ipaddress.ip_address(v)
        return IOCType.IP
    except ValueError:
        pass
    if low.startswith(("http://", "https://", "ftp://")):
        return IOCType.URL
    if _EMAIL_RE.match(low):
        return IOCType.EMAIL
    if _DOMAIN_RE.match(low):
        return IOCType.DOMAIN
    return None


def ioc_id(ioc_type: IOCType, canonical_value: str) -> str:
    return hashlib.sha256(
        f"{IOCType.coerce(ioc_type).value}|{canonical_value}".encode("utf-8")
    ).hexdigest()[:32]


@dataclass
class IOC:
    ioc_type: IOCType
    value: str                       # canonical
    role: str = ""                   # c2 | payload_delivery | phishing | ...
    malware: str = ""                # associated family (as reported)
    campaign: str = ""               # associated campaign (as reported)
    actor: str = ""                  # associated actor (as reported)
    tags: List[str] = field(default_factory=list)
    tlp: TLP = TLP.CLEAR
    first_seen: float = 0.0
    last_seen: float = 0.0
    evidence: EvidenceBundle = field(default_factory=EvidenceBundle)

    def __post_init__(self) -> None:
        self.ioc_type = IOCType.coerce(self.ioc_type)
        self.tlp = TLP.coerce(self.tlp)
        if isinstance(self.evidence, list):
            self.evidence = EvidenceBundle.from_list(self.evidence)

    @property
    def id(self) -> str:
        return ioc_id(self.ioc_type, self.value)

    def defanged(self) -> str:
        if self.ioc_type in (IOCType.URL, IOCType.DOMAIN):
            if _HAVE_URLKIT and hasattr(_urlkit, "defang"):
                try:
                    return _urlkit.defang(self.value)
                except Exception:
                    pass
            return self.value.replace("http", "hxxp").replace(".", "[.]")
        if self.ioc_type in (IOCType.IP, IOCType.CIDR):
            return self.value.replace(".", "[.]")
        return self.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "type": self.ioc_type.value, "value": self.value,
            "defanged": self.defanged(), "role": self.role,
            "malware": self.malware, "campaign": self.campaign,
            "actor": self.actor, "tags": list(self.tags), "tlp": self.tlp.value,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "evidence": self.evidence.to_list(),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IOC":
        return cls(
            ioc_type=IOCType.coerce(d.get("type")),
            value=str(d.get("value", "")),
            role=str(d.get("role", "")),
            malware=str(d.get("malware", "")),
            campaign=str(d.get("campaign", "")),
            actor=str(d.get("actor", "")),
            tags=list(d.get("tags", []) or []),
            tlp=TLP.coerce(d.get("tlp")),
            first_seen=float(d.get("first_seen", 0.0) or 0.0),
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
            evidence=EvidenceBundle.from_list(d.get("evidence", []) or []),
        )

    @classmethod
    def parse(cls, raw: str, **kw) -> "IOC":
        """Construct from a raw string, inferring and canonicalizing the type."""
        t = detect_type(raw)
        if t is None:
            raise CanonicalizeError(f"cannot infer IOC type: {raw!r}")
        return cls(ioc_type=t, value=canonicalize(t, raw), **kw)


__all__ = ["IOC", "IOCType", "CanonicalizeError", "canonicalize", "detect_type",
           "ioc_id"]
