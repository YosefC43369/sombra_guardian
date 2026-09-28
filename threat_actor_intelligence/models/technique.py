"""
threat_actor_intelligence.models.technique — MITRE ATT&CK / CAPEC objects.

Typed models for ATT&CK techniques, sub-techniques, tactics and mitigations, and
CAPEC attack patterns. These are *reference knowledge* objects (the framework),
distinct from the observational objects (actors/campaigns) that map onto them.
Ids follow the public schema (``T1059``, ``T1059.001``, ``TA0002``, ``M1042``,
``CAPEC-66``) so external references resolve directly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_RE = re.compile(r"^TA\d{4}$")
_MITIGATION_RE = re.compile(r"^M\d{4}$")
_CAPEC_RE = re.compile(r"^CAPEC-\d+$", re.IGNORECASE)

# Canonical ATT&CK Enterprise tactic ordering (kill-chain order) for timelines
# and coverage matrices.
ENTERPRISE_TACTICS: List[tuple] = [
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]
_TACTIC_ORDER = {short: i for i, (_, short, _) in enumerate(ENTERPRISE_TACTICS)}
_TACTIC_BY_ID = {tid: (short, name) for tid, short, name in ENTERPRISE_TACTICS}


def tactic_order(short_name: str) -> int:
    return _TACTIC_ORDER.get((short_name or "").strip().lower(), 999)


class ATTACKDomain(str, Enum):
    ENTERPRISE = "enterprise-attack"
    MOBILE = "mobile-attack"
    ICS = "ics-attack"

    @classmethod
    def coerce(cls, raw: Any) -> "ATTACKDomain":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.ENTERPRISE


@dataclass
class Tactic:
    tactic_id: str                   # TA0002
    short_name: str = ""             # execution
    name: str = ""                   # Execution
    description: str = ""
    domain: ATTACKDomain = ATTACKDomain.ENTERPRISE
    references: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.domain = ATTACKDomain.coerce(self.domain)
        if not self.short_name and self.tactic_id in _TACTIC_BY_ID:
            self.short_name, self.name = _TACTIC_BY_ID[self.tactic_id]

    @property
    def order(self) -> int:
        return tactic_order(self.short_name)

    def to_dict(self) -> Dict[str, Any]:
        return {"tactic_id": self.tactic_id, "short_name": self.short_name,
                "name": self.name, "description": self.description,
                "domain": self.domain.value, "order": self.order,
                "references": list(self.references)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Tactic":
        return cls(tactic_id=str(d.get("tactic_id", "")),
                   short_name=str(d.get("short_name", "")),
                   name=str(d.get("name", "")),
                   description=str(d.get("description", "")),
                   domain=ATTACKDomain.coerce(d.get("domain")),
                   references=list(d.get("references", []) or []))


@dataclass
class Technique:
    technique_id: str                # T1059 or T1059.001
    name: str = ""
    description: str = ""
    tactics: List[str] = field(default_factory=list)   # short names
    domain: ATTACKDomain = ATTACKDomain.ENTERPRISE
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection: str = ""
    is_subtechnique: bool = False
    parent_id: str = ""              # for sub-techniques
    mitigations: List[str] = field(default_factory=list)   # mitigation ids
    deprecated: bool = False
    references: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.domain = ATTACKDomain.coerce(self.domain)
        if "." in self.technique_id and not self.is_subtechnique:
            self.is_subtechnique = True
        if self.is_subtechnique and not self.parent_id and "." in self.technique_id:
            self.parent_id = self.technique_id.split(".", 1)[0]

    @property
    def valid_id(self) -> bool:
        return bool(_TECHNIQUE_RE.match(self.technique_id or ""))

    @property
    def primary_tactic(self) -> str:
        if not self.tactics:
            return ""
        return min(self.tactics, key=tactic_order)

    def to_dict(self) -> Dict[str, Any]:
        return {"technique_id": self.technique_id, "name": self.name,
                "description": self.description, "tactics": list(self.tactics),
                "domain": self.domain.value, "platforms": list(self.platforms),
                "data_sources": list(self.data_sources), "detection": self.detection,
                "is_subtechnique": self.is_subtechnique, "parent_id": self.parent_id,
                "mitigations": list(self.mitigations), "deprecated": self.deprecated,
                "references": list(self.references)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Technique":
        return cls(technique_id=str(d.get("technique_id", "")),
                   name=str(d.get("name", "")),
                   description=str(d.get("description", "")),
                   tactics=list(d.get("tactics", []) or []),
                   domain=ATTACKDomain.coerce(d.get("domain")),
                   platforms=list(d.get("platforms", []) or []),
                   data_sources=list(d.get("data_sources", []) or []),
                   detection=str(d.get("detection", "")),
                   is_subtechnique=bool(d.get("is_subtechnique", False)),
                   parent_id=str(d.get("parent_id", "")),
                   mitigations=list(d.get("mitigations", []) or []),
                   deprecated=bool(d.get("deprecated", False)),
                   references=list(d.get("references", []) or []))


@dataclass
class Mitigation:
    mitigation_id: str               # M1042
    name: str = ""
    description: str = ""
    techniques: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"mitigation_id": self.mitigation_id, "name": self.name,
                "description": self.description, "techniques": list(self.techniques),
                "references": list(self.references)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Mitigation":
        return cls(mitigation_id=str(d.get("mitigation_id", "")),
                   name=str(d.get("name", "")),
                   description=str(d.get("description", "")),
                   techniques=list(d.get("techniques", []) or []),
                   references=list(d.get("references", []) or []))


@dataclass
class CAPECPattern:
    capec_id: str                    # CAPEC-66
    name: str = ""
    description: str = ""
    abstraction: str = ""            # Meta | Standard | Detailed
    likelihood: str = ""
    severity: str = ""
    related_techniques: List[str] = field(default_factory=list)  # ATT&CK ids
    related_weaknesses: List[str] = field(default_factory=list)  # CWE ids
    references: List[str] = field(default_factory=list)

    @property
    def valid_id(self) -> bool:
        return bool(_CAPEC_RE.match(self.capec_id or ""))

    def to_dict(self) -> Dict[str, Any]:
        return {"capec_id": self.capec_id, "name": self.name,
                "description": self.description, "abstraction": self.abstraction,
                "likelihood": self.likelihood, "severity": self.severity,
                "related_techniques": list(self.related_techniques),
                "related_weaknesses": list(self.related_weaknesses),
                "references": list(self.references)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CAPECPattern":
        return cls(capec_id=str(d.get("capec_id", "")),
                   name=str(d.get("name", "")),
                   description=str(d.get("description", "")),
                   abstraction=str(d.get("abstraction", "")),
                   likelihood=str(d.get("likelihood", "")),
                   severity=str(d.get("severity", "")),
                   related_techniques=list(d.get("related_techniques", []) or []),
                   related_weaknesses=list(d.get("related_weaknesses", []) or []),
                   references=list(d.get("references", []) or []))


def is_technique_id(v: str) -> bool:
    return bool(_TECHNIQUE_RE.match((v or "").strip()))


def is_tactic_id(v: str) -> bool:
    return bool(_TACTIC_RE.match((v or "").strip()))


def normalize_technique_id(v: str) -> str:
    """Uppercase, strip, and validate a technique id; '' if not a technique id."""
    s = (v or "").strip().upper()
    return s if _TECHNIQUE_RE.match(s) else ""


__all__ = ["ATTACKDomain", "Tactic", "Technique", "Mitigation", "CAPECPattern",
           "ENTERPRISE_TACTICS", "tactic_order", "is_technique_id", "is_tactic_id",
           "normalize_technique_id"]
