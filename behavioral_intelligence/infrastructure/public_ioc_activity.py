"""
behavioral_intelligence.infrastructure.public_ioc_activity — public IOC reference
behaviour (spec §26).

Tracks how indicators of compromise are referenced in public content over time:
IPs, domains, URLs, hashes, CVEs, malware-family names, ASNs and certificates.
For each indicator it records first/last-seen, frequency, the platforms it
appeared on and the accounts/entities associated with it. This is the blue-team
enrichment view — "when did this indicator start showing up publicly, and
where" — built entirely from public observations.

Where the repository's threat-intelligence layer is importable, matched
indicators can be cross-referenced against it for enrichment; the import is
defensive so this module runs standalone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..models.observation import Observation
from ..content.entity_extractor import extract_from_text

# Optional cross-reference with the repo's threat-intel engine.
try:  # pragma: no cover - optional integration
    import findings as _findings
    HAVE_FINDINGS = True
except Exception:  # pragma: no cover
    _findings = None  # type: ignore[assignment]
    HAVE_FINDINGS = False

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ASN_RE = re.compile(r"\bAS\d{2,7}\b", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA_RE = re.compile(r"\b[a-fA-F0-9]{40}(?:[a-fA-F0-9]{24})?\b")
# small illustrative malware-family lexicon; extend via config/threat-intel feed
_MALWARE_FAMILIES = {
    "emotet", "trickbot", "cobaltstrike", "cobalt strike", "qakbot", "qbot",
    "lockbit", "revil", "conti", "mirai", "agenttesla", "redline", "raccoon",
    "icedid", "bumblebee", "gootloader", "log4shell", "follina",
}


@dataclass
class IOCActivity:
    indicator: str = ""
    ioc_type: str = ""            # ip|domain|url|hash|cve|asn|malware|certificate
    frequency: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    platforms: List[str] = field(default_factory=list)
    associated_accounts: List[str] = field(default_factory=list)
    threat_intel_match: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        return {"indicator": self.indicator, "ioc_type": self.ioc_type,
                "frequency": self.frequency, "first_seen": self.first_seen,
                "last_seen": self.last_seen, "platforms": self.platforms,
                "associated_accounts": self.associated_accounts,
                "threat_intel_match": self.threat_intel_match}


def _iocs_in(o: Observation) -> List[tuple]:
    """Return (ioc_type, value) tuples found in an observation."""
    out: List[tuple] = []
    text = o.text or ""
    extracted = extract_from_text(text)
    for v in extracted.get("ipv4", []) + extracted.get("ipv6", []):
        out.append(("ip", v))
    for v in extracted.get("url", []):
        out.append(("url", v))
    for d in o.all_domains():
        out.append(("domain", d))
    for v in extracted.get("btc", []) + extracted.get("eth", []):
        out.append(("wallet", v))
    for m in _CVE_RE.findall(text):
        out.append(("cve", m.upper()))
    for m in _ASN_RE.findall(text):
        out.append(("asn", m.upper()))
    for m in _SHA_RE.findall(text):
        out.append(("hash", m.lower()))
    for m in _MD5_RE.findall(text):
        out.append(("hash", m.lower()))
    low = text.lower()
    for fam in _MALWARE_FAMILIES:
        if fam in low:
            out.append(("malware", fam))
    # explicit indicators carried in metadata (e.g. from IOC providers)
    for ind in o.metadata.get("iocs", []) or []:
        if isinstance(ind, dict):
            out.append((str(ind.get("type", "unknown")), str(ind.get("value", ""))))
    return [(t, v) for t, v in out if v]


def analyze_ioc_activity(observations: Sequence[Observation], *,
                         enrich: bool = False, top_n: int = 100
                         ) -> List[IOCActivity]:
    agg: Dict[tuple, IOCActivity] = {}
    for o in observations:
        for ioc_type, value in _iocs_in(o):
            key = (ioc_type, value.lower())
            act = agg.get(key)
            if act is None:
                act = IOCActivity(indicator=value, ioc_type=ioc_type)
                agg[key] = act
            act.frequency += 1
            if o.platform and o.platform not in act.platforms:
                act.platforms.append(o.platform)
            if o.account_id and o.account_id not in act.associated_accounts:
                act.associated_accounts.append(o.account_id)
            if o.has_time:
                act.first_seen = (o.timestamp if act.first_seen == 0
                                  else min(act.first_seen, o.timestamp))
                act.last_seen = max(act.last_seen, o.timestamp)

    results = sorted(agg.values(), key=lambda a: a.frequency, reverse=True)[:top_n]
    if enrich and HAVE_FINDINGS:
        for act in results:
            act.threat_intel_match = _enrich(act)
    return results


def _enrich(act: IOCActivity) -> Optional[Dict[str, object]]:  # pragma: no cover
    """Best-effort cross-reference against the repo's findings/threat-intel store.
    Returns a small match summary or None. Never raises."""
    try:
        if hasattr(_findings, "lookup_indicator"):
            match = _findings.lookup_indicator(act.indicator)
            if match:
                return {"source": "findings", "match": bool(match)}
    except Exception:
        return None
    return None
