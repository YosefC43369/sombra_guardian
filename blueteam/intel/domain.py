"""
blueteam/intel/domain.py — Threat Intel domain layer (pure; no telegram/sqlite).

The central :class:`IOC` model, deterministic canonicalization (shared with Link
Guard via :mod:`blueteam.urlkit`), the explainable confidence model, and a
deterministic STIX 2.1-lite export. Imports only stdlib, the shared pure utils
(``urlkit``), and nothing from services/adapters — enforced by the arch tests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .. import urlkit

# Deterministic namespace for STIX UUIDv5 (stable ids across runs/exports).
_STIX_NS = uuid.UUID("6b61736f-6d62-7261-2d69-6f632d6e7331")

_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class IOCType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    TME_HANDLE = "tme_handle"
    WALLET = "wallet"
    ADVISORY = "advisory"        # CISA-KEV-style; reporting only, no matching

    @classmethod
    def coerce(cls, v) -> "IOCType":
        if isinstance(v, cls):
            return v                     # already a member; str(member) != value on 3.11+
        try:
            return cls(str(v).strip().lower())
        except ValueError:
            return cls.URL


class TLP(str, Enum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class CanonicalizeError(ValueError):
    pass


def canonicalize(ioc_type: IOCType, value: str) -> str:
    """Deterministic canonical form per type. Raises CanonicalizeError on invalid."""
    v = (value or "").strip()
    if not v:
        raise CanonicalizeError("empty value")
    t = IOCType.coerce(ioc_type)
    if t == IOCType.URL:
        return urlkit.canonicalize(v)
    if t == IOCType.DOMAIN:
        host = v.lower().rstrip(".")
        host = host.split("/")[0].split("@")[-1]
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass
        if "." not in host or " " in host:
            raise CanonicalizeError(f"not a domain: {value!r}")
        return host
    if t == IOCType.IP:
        return str(ipaddress.ip_address(v))
    if t == IOCType.CIDR:
        return str(ipaddress.ip_network(v, strict=False))
    if t in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        h = v.lower()
        rx = {IOCType.MD5: _MD5_RE, IOCType.SHA1: _SHA1_RE, IOCType.SHA256: _SHA256_RE}[t]
        if not rx.match(h):
            raise CanonicalizeError(f"invalid {t.value} hash: {value!r}")
        return h
    if t == IOCType.EMAIL:
        e = v.lower()
        if not _EMAIL_RE.match(e):
            raise CanonicalizeError(f"invalid email: {value!r}")
        return e
    if t == IOCType.TME_HANDLE:
        h = v.lower().strip()
        for pre in ("https://t.me/", "http://t.me/", "t.me/", "@"):
            if h.startswith(pre):
                h = h[len(pre):]
        h = h.split("/")[0].split("?")[0]
        if not h:
            raise CanonicalizeError(f"invalid t.me handle: {value!r}")
        return h
    if t == IOCType.WALLET:
        return v.strip()            # case can be significant; trim only
    if t == IOCType.ADVISORY:
        return v.strip().upper()
    return v


def detect_type(value: str) -> Optional[IOCType]:
    """Best-effort type inference for /intel lookup <ioc> and add."""
    v = (value or "").strip()
    if not v:
        return None
    low = v.lower()
    if _SHA256_RE.match(low):
        return IOCType.SHA256
    if _SHA1_RE.match(low):
        return IOCType.SHA1
    if _MD5_RE.match(low):
        return IOCType.MD5
    if "/" in v and _looks_cidr(v):
        return IOCType.CIDR
    try:
        ipaddress.ip_address(v)
        return IOCType.IP
    except ValueError:
        pass
    if low.startswith(("http://", "https://")):
        return IOCType.URL
    if "t.me/" in low or low.startswith("@"):
        return IOCType.TME_HANDLE
    if _EMAIL_RE.match(low):
        return IOCType.EMAIL
    if "." in low and " " not in low:
        return IOCType.DOMAIN
    return None


def _looks_cidr(v: str) -> bool:
    try:
        ipaddress.ip_network(v, strict=False)
        return "/" in v
    except ValueError:
        return False


def ioc_id(ioc_type: IOCType, canonical_value: str) -> str:
    return hashlib.sha256(
        f"{IOCType.coerce(ioc_type).value}|{canonical_value}".encode("utf-8")
    ).hexdigest()


# ---------------- confidence model (explainable) ----------------

# Per-source trust weights (0..1). Unknown sources default to 0.5.
DEFAULT_SOURCE_WEIGHTS = {
    "local": 1.0, "urlhaus": 0.85, "openphish": 0.8, "threatfox": 0.85,
    "malwarebazaar": 0.9, "cisa_kev": 0.95,
}


def _freshness_factor(age_days: float, half_life_days: float = 30.0) -> float:
    """Exponential-ish decay in [0,1]: 1.0 fresh, 0.5 at one half-life."""
    if age_days <= 0:
        return 1.0
    return 0.5 ** (age_days / max(1e-6, half_life_days))


def compute_confidence(*, sources: List[str], age_days: float,
                       local_verdict: bool = False, fp_reports: int = 0,
                       source_weights: Optional[Dict[str, float]] = None
                       ) -> Tuple[int, Dict[str, Any]]:
    """Explainable confidence in [0,100] with a stored breakdown.

    = base(best source) * freshness, boosted by independent corroboration
    (noisy-OR across distinct sources), + local-verdict boost, - fp penalty.
    """
    weights = source_weights or DEFAULT_SOURCE_WEIGHTS
    distinct = sorted(set(s for s in sources if s))
    if not distinct:
        distinct = ["unknown"]
    # noisy-OR over per-source weights -> corroboration
    prod = 1.0
    for s in distinct:
        prod *= (1.0 - weights.get(s, 0.5))
    corroboration = 1.0 - prod
    freshness = _freshness_factor(age_days)
    base = corroboration * freshness
    local_boost = 0.15 if local_verdict else 0.0
    fp_penalty = min(0.5, 0.1 * max(0, fp_reports))
    score = max(0.0, min(1.0, base + local_boost - fp_penalty))
    breakdown = {
        "sources": distinct,
        "corroboration": round(corroboration, 4),
        "freshness": round(freshness, 4),
        "age_days": round(age_days, 2),
        "local_boost": local_boost,
        "fp_penalty": round(fp_penalty, 4),
        "final": round(score, 4),
    }
    return int(round(score * 100)), breakdown


@dataclass
class IOC:
    ioc_type: IOCType
    value: str                       # canonical
    sources: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    expires_at: Optional[float] = None
    confidence: int = 50
    severity: str = "medium"
    tlp: TLP = TLP.AMBER
    tags: List[str] = field(default_factory=list)
    attack: str = ""
    family: str = ""
    provenance: Dict[str, Any] = field(default_factory=dict)
    is_local: bool = False

    def __post_init__(self):
        self.ioc_type = IOCType.coerce(self.ioc_type)
        if isinstance(self.tlp, str):
            try:
                self.tlp = TLP(self.tlp)
            except ValueError:
                self.tlp = TLP.AMBER

    @property
    def id(self) -> str:
        return ioc_id(self.ioc_type, self.value)

    def is_expired(self, now: float) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def defanged(self) -> str:
        if self.ioc_type in (IOCType.URL, IOCType.DOMAIN):
            return urlkit.defang(self.value)
        if self.ioc_type in (IOCType.IP, IOCType.CIDR):
            return self.value.replace(".", "[.]")
        return self.value

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "type": self.ioc_type.value, "value": self.value,
                "defanged": self.defanged(), "sources": list(self.sources),
                "first_seen": self.first_seen, "last_seen": self.last_seen,
                "expires_at": self.expires_at, "confidence": self.confidence,
                "severity": self.severity, "tlp": self.tlp.value,
                "tags": list(self.tags), "attack": self.attack,
                "family": self.family, "is_local": self.is_local,
                "provenance": dict(self.provenance)}


# ---------------- STIX 2.1-lite export (deterministic) ----------------

_STIX_PATTERN = {
    IOCType.URL: "[url:value = '{v}']",
    IOCType.DOMAIN: "[domain-name:value = '{v}']",
    IOCType.IP: "[ipv4-addr:value = '{v}']",
    IOCType.CIDR: "[ipv4-addr:value = '{v}']",
    IOCType.MD5: "[file:hashes.'MD5' = '{v}']",
    IOCType.SHA1: "[file:hashes.'SHA-1' = '{v}']",
    IOCType.SHA256: "[file:hashes.'SHA-256' = '{v}']",
    IOCType.EMAIL: "[email-addr:value = '{v}']",
}


def _stix_id(kind: str, ioc: IOC) -> str:
    return f"{kind}--{uuid.uuid5(_STIX_NS, kind + '|' + ioc.id)}"


def to_stix_bundle(iocs: List[IOC]) -> Dict[str, Any]:
    """Deterministic STIX 2.1-lite bundle (indicator + malware objects). ids are
    UUIDv5 from type+value, so re-exporting the same IOCs yields identical ids."""
    objects: List[Dict[str, Any]] = []
    families: Dict[str, str] = {}
    for ioc in iocs:
        pattern_tpl = _STIX_PATTERN.get(ioc.ioc_type)
        if pattern_tpl is None:
            continue
        safe_v = ioc.value.replace("'", "")
        ind_id = _stix_id("indicator", ioc)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "name": f"{ioc.ioc_type.value}:{ioc.value}",
            "pattern": pattern_tpl.format(v=safe_v), "pattern_type": "stix",
            "confidence": ioc.confidence,
            "labels": ([ioc.severity] + list(ioc.tags)) or ["malicious-activity"],
        })
        if ioc.family:
            fam = families.get(ioc.family)
            if fam is None:
                fam = f"malware--{uuid.uuid5(_STIX_NS, 'malware|' + ioc.family)}"
                families[ioc.family] = fam
                objects.append({"type": "malware", "spec_version": "2.1", "id": fam,
                                "name": ioc.family, "is_family": True})
    return {"type": "bundle",
            "id": f"bundle--{uuid.uuid5(_STIX_NS, 'bundle|' + '|'.join(sorted(i.id for i in iocs)))}",
            "objects": objects}


__all__ = ["IOC", "IOCType", "TLP", "CanonicalizeError", "canonicalize",
           "detect_type", "ioc_id", "compute_confidence", "to_stix_bundle",
           "DEFAULT_SOURCE_WEIGHTS"]
