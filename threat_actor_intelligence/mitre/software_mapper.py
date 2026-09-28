"""
threat_actor_intelligence.mitre.software_mapper — malware names ⇒ ATT&CK software.

Bridges the engine's own ``MalwareFamily`` objects to ATT&CK ``Software``
(S#### ) objects by name/alias, so a family ingested from a vendor report inherits
the ATT&CK-documented technique set for that software when a confident name match
exists. Matching is exact-or-alias only (no fuzzy guessing) because a wrong
software match would silently attribute techniques the family may not use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..models.malware_family import MalwareFamily
from ..models.software import Software
from .attack_engine import ATTACKEngine


@dataclass
class SoftwareMatch:
    family_id: str
    software_id: str
    software_name: str
    matched_alias: str
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"family_id": self.family_id, "software_id": self.software_id,
                "software_name": self.software_name,
                "matched_alias": self.matched_alias,
                "techniques": list(self.techniques)}


class SoftwareMapper:
    def __init__(self, attack: Optional[ATTACKEngine] = None):
        self.attack = attack

    def match(self, family: MalwareFamily) -> Optional[SoftwareMatch]:
        if not self.attack:
            return None
        candidates = [family.family_name] + [a.name for a in family.aliases]
        for cand in candidates:
            sw: Optional[Software] = self.attack.resolve_software(cand)
            if sw:
                return SoftwareMatch(family_id=family.family_id,
                                     software_id=sw.software_id,
                                     software_name=sw.name, matched_alias=cand,
                                     techniques=list(sw.techniques))
        return None

    def enrich(self, family: MalwareFamily) -> Optional[SoftwareMatch]:
        """Match and, if found, fold the ATT&CK software id + techniques into the
        family (idempotent). Returns the match, or None."""
        m = self.match(family)
        if not m:
            return None
        if not family.attack_software_id:
            family.attack_software_id = m.software_id
        for tid in m.techniques:
            family.link("techniques", tid)
        return m


__all__ = ["SoftwareMapper", "SoftwareMatch"]
