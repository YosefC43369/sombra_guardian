"""
threat_actor_intelligence.mitre.capec_engine — MITRE CAPEC attack patterns.

CAPEC describes *attack patterns* (how) and cross-references ATT&CK techniques
and CWE weaknesses. This engine loads CAPEC from the public JSON export (a list
of pattern objects, or the STIX-style bundle MITRE also ships) and answers:

    capec        -> related ATT&CK techniques / CWEs
    technique    -> CAPEC patterns that reference it (reverse index)

As with ATT&CK it carries a small offline seed so the mapping works without the
full catalog. CAPEC never contributes exploit content — only the public pattern
metadata (id, name, abstraction, likelihood/severity, cross-refs).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..models.technique import CAPECPattern, normalize_technique_id


class CAPECEngine:
    def __init__(self) -> None:
        self.patterns: Dict[str, CAPECPattern] = {}
        self._by_technique: Dict[str, List[str]] = {}   # ATT&CK id -> [CAPEC ids]

    def add(self, pattern: CAPECPattern) -> None:
        if not pattern.capec_id:
            return
        self.patterns[pattern.capec_id.upper()] = pattern
        for tid in pattern.related_techniques:
            nid = normalize_technique_id(tid) or tid.upper()
            self._by_technique.setdefault(nid, [])
            if pattern.capec_id.upper() not in self._by_technique[nid]:
                self._by_technique[nid].append(pattern.capec_id.upper())

    def load_json(self, text: str) -> int:
        data = json.loads(text)
        objs = data.get("objects", data) if isinstance(data, dict) else data
        return self.load_objects(objs)

    def load_objects(self, objs: List[Dict[str, Any]]) -> int:
        n = 0
        for obj in objs or []:
            p = self._parse(obj)
            if p:
                self.add(p)
                n += 1
        return n

    def _parse(self, obj: Dict[str, Any]) -> Optional[CAPECPattern]:
        # Accept both a plain capec dict and a STIX attack-pattern with a
        # capec external reference.
        cid = ""
        techniques: List[str] = []
        weaknesses: List[str] = []
        refs: List[str] = []
        for ref in obj.get("external_references", []) or []:
            src = ref.get("source_name", "")
            if src == "capec" and ref.get("external_id"):
                cid = ref["external_id"]
            elif src.startswith("ATTACK") or src == "mitre-attack":
                if ref.get("external_id"):
                    techniques.append(ref["external_id"])
            elif src == "cwe" and ref.get("external_id"):
                weaknesses.append(ref["external_id"])
            if ref.get("url"):
                refs.append(ref["url"])
        cid = cid or obj.get("capec_id", "") or obj.get("id", "")
        if cid and not cid.upper().startswith("CAPEC-"):
            if str(cid).isdigit():
                cid = f"CAPEC-{cid}"
        if not cid:
            return None
        techniques = techniques or obj.get("related_techniques", []) or []
        weaknesses = weaknesses or obj.get("related_weaknesses", []) or []
        return CAPECPattern(
            capec_id=cid.upper(), name=obj.get("name", ""),
            description=obj.get("description", ""),
            abstraction=obj.get("abstraction", obj.get("x_capec_abstraction", "")),
            likelihood=obj.get("likelihood", obj.get("x_capec_likelihood_of_attack", "")),
            severity=obj.get("severity", obj.get("x_capec_typical_severity", "")),
            related_techniques=techniques, related_weaknesses=weaknesses,
            references=refs)

    def get(self, capec_id: str) -> Optional[CAPECPattern]:
        return self.patterns.get((capec_id or "").upper())

    def patterns_for_technique(self, technique_id: str) -> List[CAPECPattern]:
        nid = normalize_technique_id(technique_id) or (technique_id or "").upper()
        return [self.patterns[c] for c in self._by_technique.get(nid, [])
                if c in self.patterns]

    def techniques_for_pattern(self, capec_id: str) -> List[str]:
        p = self.get(capec_id)
        return list(p.related_techniques) if p else []

    def stats(self) -> Dict[str, int]:
        return {"patterns": len(self.patterns),
                "mapped_techniques": len(self._by_technique)}

    def load_seed(self) -> "CAPECEngine":
        seed = [
            ("CAPEC-98", "Phishing", "Standard", ["T1566"], ["CWE-451"]),
            ("CAPEC-163", "Spear Phishing", "Detailed", ["T1566.001", "T1566.002"],
             ["CWE-451"]),
            ("CAPEC-242", "Code Injection", "Meta", ["T1059"], ["CWE-94"]),
            ("CAPEC-549", "Local Execution of Code", "Standard", ["T1059.001"],
             ["CWE-94"]),
            ("CAPEC-640", "Inclusion of Code in Existing Process", "Detailed",
             ["T1055"], ["CWE-94"]),
            ("CAPEC-509", "Kerberoasting", "Detailed", ["T1003"], ["CWE-522"]),
            ("CAPEC-116", "Excavation", "Meta", ["T1082"], ["CWE-200"]),
            ("CAPEC-555", "Remote Services with Stolen Credentials", "Detailed",
             ["T1021"], ["CWE-522"]),
        ]
        for cid, name, abstraction, techs, cwes in seed:
            self.add(CAPECPattern(capec_id=cid, name=name, abstraction=abstraction,
                                  related_techniques=techs, related_weaknesses=cwes,
                                  references=[f"https://capec.mitre.org/data/"
                                              f"definitions/{cid.split('-')[1]}.html"]))
        return self


__all__ = ["CAPECEngine"]
