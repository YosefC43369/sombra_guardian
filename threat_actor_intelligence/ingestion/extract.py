"""
threat_actor_intelligence.ingestion.extract — IOC / CVE / technique extraction.

A pure, reusable text miner used by the RSS, vendor and report parsers. It pulls
defanged and plain indicators, CVE ids, ATT&CK technique ids and a conservative
set of actor/malware name candidates out of free text. Everything is
canonicalized through the model layer so the same indicator deduplicates
regardless of how a source wrote it (``hxxps://evil[.]com`` == ``evil.com``).

Name extraction is intentionally low-recall/high-precision: it only proposes
names that match well-known naming conventions (APT##, UNC####, TA###, and
capitalized codenames adjacent to cue words like "group", "campaign",
"malware"), because a false actor name is worse than a missed one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..models.ioc import IOC, IOCType, canonicalize, CanonicalizeError

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|"
                      r"\b[0-9a-fA-F]{64}\b")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
                    r"(?:\[?\.\]?)){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[?\.\]?))+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|us|uk|de|fr|nl|gov|edu|"
    r"mil|int|eu|site|online|club|shop|app|dev|cloud|live|tk|ml|ga|cf|gq))\b",
    re.IGNORECASE)
_URL_RE = re.compile(r"\b(?:h[xX]{2}ps?|https?)://[^\s<>\"')]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.\[\]-]+\.[a-z]{2,}\b", re.IGNORECASE)
_ASN_RE = re.compile(r"\bAS\d{2,7}\b", re.IGNORECASE)

_APT_RE = re.compile(r"\b(?:APT|UNC|TA|FIN|TEMP|DEV|G)[-\s]?\d{1,5}\b", re.IGNORECASE)
_CUE_WORDS = ("group", "campaign", "malware", "backdoor", "loader", "ransomware",
              "trojan", "actor", "gang", "operation", "botnet", "stealer", "rat")

# Domains that are common false positives (documentation, refs). Skipped.
_FP_DOMAINS = {"attack.mitre.org", "capec.mitre.org", "cve.mitre.org",
               "nvd.nist.gov", "cisa.gov", "github.com", "twitter.com",
               "example.com", "microsoft.com", "google.com", "virustotal.com"}


@dataclass
class Extraction:
    iocs: List[IOC] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    technique_ids: List[str] = field(default_factory=list)
    actor_names: List[str] = field(default_factory=list)
    malware_names: List[str] = field(default_factory=list)

    def dedupe(self) -> "Extraction":
        seen: Set[str] = set()
        uniq: List[IOC] = []
        for i in self.iocs:
            if i.id not in seen:
                seen.add(i.id)
                uniq.append(i)
        self.iocs = uniq
        self.cve_ids = sorted({c.upper() for c in self.cve_ids})
        self.technique_ids = sorted({t.upper() for t in self.technique_ids})
        self.actor_names = sorted(set(self.actor_names))
        self.malware_names = sorted(set(self.malware_names))
        return self


def _add(iocs: List[IOC], itype: IOCType, raw: str) -> None:
    try:
        val = canonicalize(itype, raw)
    except CanonicalizeError:
        return
    iocs.append(IOC(ioc_type=itype, value=val))


def extract(text: str, *, mine_names: bool = True) -> Extraction:
    text = text or ""
    ex = Extraction()
    iocs: List[IOC] = []

    for m in _URL_RE.finditer(text):
        _add(iocs, IOCType.URL, m.group(0))
    for m in _EMAIL_RE.finditer(text):
        _add(iocs, IOCType.EMAIL, m.group(0))
    for m in _HASH_RE.finditer(text):
        h = m.group(0).lower()
        t = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}[len(h)]
        _add(iocs, t, h)
    for m in _IP_RE.finditer(text):
        _add(iocs, IOCType.IP, m.group(0))
    for m in _ASN_RE.finditer(text):
        _add(iocs, IOCType.ASN, m.group(0))
    for m in _DOMAIN_RE.finditer(text):
        raw = m.group(0)
        try:
            dv = canonicalize(IOCType.DOMAIN, raw)
        except CanonicalizeError:
            continue
        if dv in _FP_DOMAINS:
            continue
        iocs.append(IOC(ioc_type=IOCType.DOMAIN, value=dv))

    ex.iocs = iocs
    ex.cve_ids = [m.group(0).upper() for m in _CVE_RE.finditer(text)]
    ex.technique_ids = [m.group(0).upper() for m in _TECH_RE.finditer(text)]

    if mine_names:
        ex.actor_names = _mine_actor_names(text)
        ex.malware_names = _mine_malware_names(text)
    return ex.dedupe()


def _mine_actor_names(text: str) -> List[str]:
    names: Set[str] = set()
    for m in _APT_RE.finditer(text):
        names.add(re.sub(r"\s+", "", m.group(0)).upper())
    # capitalized codeword pairs near cue words: "Cozy Bear group"
    for m in re.finditer(r"\b([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})\s+(?:%s)\b"
                         % "|".join(_CUE_WORDS), text):
        cand = m.group(1).strip()
        if cand.lower() not in ("the", "this", "a", "an"):
            names.add(cand)
    return sorted(names)


def _mine_malware_names(text: str) -> List[str]:
    names: Set[str] = set()
    for m in re.finditer(r"\b([A-Z][A-Za-z0-9_]{2,})\s+(?:malware|backdoor|loader|"
                         r"ransomware|trojan|stealer|rat|botnet|implant)\b", text):
        names.add(m.group(1).strip())
    # "the FOO family"
    for m in re.finditer(r"\b([A-Z][A-Za-z0-9_]{2,})\s+family\b", text):
        names.add(m.group(1).strip())
    return sorted(names)


__all__ = ["Extraction", "extract"]
