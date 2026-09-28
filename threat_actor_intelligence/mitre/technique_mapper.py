"""
threat_actor_intelligence.mitre.technique_mapper — extract ATT&CK technique
references from free text.

Reports rarely tag their techniques cleanly. This mapper pulls technique ids two
ways: (1) explicit ``T####`` / ``T####.###`` mentions via regex, validated
against the loaded ATT&CK engine, and (2) a curated keyword→technique lexicon for
the most common phrasings ("spearphishing attachment", "powershell",
"credential dumping"). It returns typed ``TechniqueHit`` objects carrying the
matched span so the extraction is auditable, never a bare id list.

It is deliberately conservative: a keyword hit only fires when the phrase is
present, and every hit records *why* it matched, so a human can verify the map.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models.technique import normalize_technique_id, is_technique_id
from .attack_engine import ATTACKEngine

_TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Curated keyword → technique lexicon. Phrases are matched case-insensitively as
# whole-word boundaries. Kept small and high-precision on purpose.
KEYWORD_TECHNIQUES: Dict[str, str] = {
    "spearphishing attachment": "T1566.001",
    "spear-phishing attachment": "T1566.001",
    "spearphishing link": "T1566.002",
    "spear-phishing link": "T1566.002",
    "phishing email": "T1566",
    "phishing": "T1566",
    "powershell": "T1059.001",
    "windows command shell": "T1059.003",
    "cmd.exe": "T1059.003",
    "command and scripting": "T1059",
    "process injection": "T1055",
    "dll injection": "T1055",
    "process hollowing": "T1055",
    "obfuscated": "T1027",
    "obfuscation": "T1027",
    "packed": "T1027",
    "credential dumping": "T1003",
    "lsass": "T1003",
    "mimikatz": "T1003",
    "system information discovery": "T1082",
    "remote services": "T1021",
    "rdp": "T1021",
    "smb": "T1021",
    "application layer protocol": "T1071",
    "http c2": "T1071.001",
    "https c2": "T1071.001",
    "web protocols": "T1071.001",
    "exfiltration over c2": "T1041",
    "data encrypted for impact": "T1486",
    "ransomware": "T1486",
    "file encryption": "T1486",
    "inhibit system recovery": "T1490",
    "delete shadow copies": "T1490",
    "vssadmin": "T1490",
    "boot or logon autostart": "T1547",
    "registry run key": "T1547",
    "scheduled task": "T1053",
}


@dataclass
class TechniqueHit:
    technique_id: str
    name: str = ""
    matched: str = ""            # the span/keyword that produced the hit
    method: str = "keyword"      # explicit | keyword
    tactics: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"technique_id": self.technique_id, "name": self.name,
                "matched": self.matched, "method": self.method,
                "tactics": list(self.tactics)}


class TechniqueMapper:
    def __init__(self, attack: Optional[ATTACKEngine] = None,
                 *, validate: bool = True):
        self.attack = attack
        self.validate = validate

    def _lookup(self, tid: str) -> TechniqueHit:
        name, tactics = "", []
        if self.attack:
            t = self.attack.technique(tid)
            if t:
                name, tactics = t.name, t.tactics
        return TechniqueHit(technique_id=tid, name=name, tactics=tactics)

    def map_text(self, text: str) -> List[TechniqueHit]:
        text = text or ""
        low = text.lower()
        hits: Dict[str, TechniqueHit] = {}

        # 1) explicit ids
        for m in _TECH_ID_RE.finditer(text):
            tid = normalize_technique_id(m.group(0))
            if not tid:
                continue
            if self.validate and self.attack and not self.attack.technique(tid):
                # unknown-to-catalog id: keep it but flag by empty name
                pass
            hit = self._lookup(tid)
            hit.matched, hit.method = m.group(0), "explicit"
            hits[tid] = hit

        # 2) keyword lexicon (longest phrases first to prefer sub-techniques)
        for phrase in sorted(KEYWORD_TECHNIQUES, key=len, reverse=True):
            if phrase in low:
                tid = KEYWORD_TECHNIQUES[phrase]
                if tid in hits:
                    continue
                hit = self._lookup(tid)
                hit.matched, hit.method = phrase, "keyword"
                hits[tid] = hit
        return sorted(hits.values(), key=lambda h: h.technique_id)

    def map_ids(self, ids: List[str]) -> List[TechniqueHit]:
        out: List[TechniqueHit] = []
        for raw in ids or []:
            tid = normalize_technique_id(raw)
            if tid:
                h = self._lookup(tid)
                h.matched, h.method = raw, "explicit"
                out.append(h)
        return out


__all__ = ["TechniqueMapper", "TechniqueHit", "KEYWORD_TECHNIQUES"]
