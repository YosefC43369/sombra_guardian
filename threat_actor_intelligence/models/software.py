"""
threat_actor_intelligence.models.software — ATT&CK software objects.

ATT&CK distinguishes *malware* and *tool* software objects (both subtypes of the
STIX ``malware``/``tool`` SDOs). This model holds the reference-catalog view of a
piece of software (its ATT&CK ``S####`` id, aliases and the techniques it
implements). It is deliberately metadata-only: no binaries, no hashes-of-samples
distribution, no capability code — only the public catalog facts.

The richer, correlation-facing malware *family* object lives in
``models.malware_family``; this one mirrors the ATT&CK Software SDO so ingested
ATT&CK bundles round-trip losslessly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

_SOFTWARE_RE = re.compile(r"^S\d{4}$")


class SoftwareType(str, Enum):
    MALWARE = "malware"
    TOOL = "tool"
    UNKNOWN = "unknown"

    @classmethod
    def coerce(cls, raw: Any) -> "SoftwareType":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class Software:
    software_id: str                 # S0154
    name: str = ""
    software_type: SoftwareType = SoftwareType.UNKNOWN
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    platforms: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)   # ATT&CK technique ids
    groups: List[str] = field(default_factory=list)        # ATT&CK group ids using it
    labels: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.software_type = SoftwareType.coerce(self.software_type)

    @property
    def valid_id(self) -> bool:
        return bool(_SOFTWARE_RE.match(self.software_id or ""))

    def to_dict(self) -> Dict[str, Any]:
        return {"software_id": self.software_id, "name": self.name,
                "software_type": self.software_type.value,
                "aliases": list(self.aliases), "description": self.description,
                "platforms": list(self.platforms), "techniques": list(self.techniques),
                "groups": list(self.groups), "labels": list(self.labels),
                "references": list(self.references)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Software":
        return cls(software_id=str(d.get("software_id", "")),
                   name=str(d.get("name", "")),
                   software_type=SoftwareType.coerce(d.get("software_type")),
                   aliases=list(d.get("aliases", []) or []),
                   description=str(d.get("description", "")),
                   platforms=list(d.get("platforms", []) or []),
                   techniques=list(d.get("techniques", []) or []),
                   groups=list(d.get("groups", []) or []),
                   labels=list(d.get("labels", []) or []),
                   references=list(d.get("references", []) or []))


__all__ = ["SoftwareType", "Software"]
