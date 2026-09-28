"""
threat_actor_intelligence.mitre.attack_engine — MITRE ATT&CK knowledge base.

Parses the public ATT&CK STIX 2.1 bundle (the ``enterprise-attack.json`` /
``mobile`` / ``ics`` collections MITRE publishes on GitHub) into the typed
reference objects (``Technique``, ``Tactic``, ``Mitigation``, ``Software`` and
ATT&CK *groups*), resolves the STIX relationship graph (``uses``,
``mitigates``, ``subtechnique-of``, ``attributed-to``), and answers the mapping
queries the correlation engines need:

    actor(group) -> techniques
    campaign     -> techniques
    software     -> techniques
    technique    -> tactics / mitigations / detection

It ships a small built-in seed so the engine — and its tests — run fully offline
with a coherent slice of ATT&CK; a real deployment loads the full bundle via
``load_stix_bundle`` (fed by ``ingestion.stix_ingestor`` /
``ingestion.mitre``-style loaders).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..models.technique import (Technique, Tactic, Mitigation, ATTACKDomain,
                                ENTERPRISE_TACTICS, normalize_technique_id)
from ..models.software import Software, SoftwareType


def _external_id(obj: Dict[str, Any], sources: Optional[Set[str]] = None) -> str:
    for ref in obj.get("external_references", []) or []:
        src = ref.get("source_name", "")
        if sources is None or src in sources:
            if ref.get("external_id"):
                return ref["external_id"]
    return ""


def _external_url(obj: Dict[str, Any]) -> List[str]:
    return [ref["url"] for ref in obj.get("external_references", []) or []
            if ref.get("url")]


# Attack-pattern kill-chain phase -> tactic short name lives in kill_chain_phases.
def _tactics_of(obj: Dict[str, Any]) -> List[str]:
    return [p.get("phase_name", "") for p in obj.get("kill_chain_phases", []) or []
            if p.get("kill_chain_name", "").endswith("attack")
            and p.get("phase_name")]


@dataclass
class ATTACKGroup:
    """An ATT&CK *group* (Gxxxx) — the framework's actor object. The engine's own
    richer ``ThreatActor`` maps onto this via ``attack_group_id``."""
    group_id: str
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    techniques: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"group_id": self.group_id, "name": self.name,
                "aliases": list(self.aliases), "description": self.description,
                "techniques": list(self.techniques), "software": list(self.software),
                "references": list(self.references)}


class ATTACKEngine:
    def __init__(self, *, domain: ATTACKDomain = ATTACKDomain.ENTERPRISE):
        self.domain = ATTACKDomain.coerce(domain)
        self.techniques: Dict[str, Technique] = {}
        self.tactics: Dict[str, Tactic] = {}
        self.mitigations: Dict[str, Mitigation] = {}
        self.software: Dict[str, Software] = {}
        self.groups: Dict[str, ATTACKGroup] = {}
        # name/alias -> canonical id resolution
        self._tech_by_name: Dict[str, str] = {}
        self._software_by_name: Dict[str, str] = {}
        self._group_by_name: Dict[str, str] = {}
        self._seed_tactics()

    def _seed_tactics(self) -> None:
        for tid, short, name in ENTERPRISE_TACTICS:
            self.tactics[tid] = Tactic(tactic_id=tid, short_name=short, name=name)

    # -- STIX bundle loading ---------------------------------------------- #

    def load_stix_bundle(self, bundle: Dict[str, Any]) -> Dict[str, int]:
        """Parse a full ATT&CK STIX 2.1 bundle. Returns a per-type count.

        Handles the object types ATT&CK uses: ``attack-pattern`` (techniques),
        ``x-mitre-tactic``, ``course-of-action`` (mitigations),
        ``malware``/``tool`` (software), ``intrusion-set`` (groups) and the
        ``relationship`` objects that wire them together."""
        objs = bundle.get("objects", []) if isinstance(bundle, dict) else []
        stix_to_attack: Dict[str, str] = {}    # stix id -> attack external id
        rels: List[Dict[str, Any]] = []
        counts = {"techniques": 0, "tactics": 0, "mitigations": 0,
                  "software": 0, "groups": 0, "relationships": 0}

        for obj in objs:
            otype = obj.get("type")
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                # still map the id so relationships resolve, but skip storing.
                if otype == "relationship":
                    pass
                else:
                    continue
            if otype == "attack-pattern":
                t = self._parse_technique(obj)
                if t:
                    self.techniques[t.technique_id] = t
                    stix_to_attack[obj["id"]] = t.technique_id
                    self._tech_by_name[t.name.lower()] = t.technique_id
                    counts["techniques"] += 1
            elif otype == "x-mitre-tactic":
                tid = _external_id(obj, {"mitre-attack"})
                short = obj.get("x_mitre_shortname", "")
                tac = Tactic(tactic_id=tid, short_name=short, name=obj.get("name", ""),
                             description=obj.get("description", ""),
                             references=_external_url(obj))
                if tid:
                    self.tactics[tid] = tac
                    stix_to_attack[obj["id"]] = tid
                    counts["tactics"] += 1
            elif otype == "course-of-action":
                mid = _external_id(obj, {"mitre-attack"})
                if mid:
                    m = Mitigation(mitigation_id=mid, name=obj.get("name", ""),
                                   description=obj.get("description", ""),
                                   references=_external_url(obj))
                    self.mitigations[mid] = m
                    stix_to_attack[obj["id"]] = mid
                    counts["mitigations"] += 1
            elif otype in ("malware", "tool"):
                sid = _external_id(obj, {"mitre-attack"})
                if sid:
                    s = Software(software_id=sid, name=obj.get("name", ""),
                                 software_type=(SoftwareType.MALWARE
                                                if otype == "malware"
                                                else SoftwareType.TOOL),
                                 aliases=obj.get("x_mitre_aliases", []) or [],
                                 description=obj.get("description", ""),
                                 platforms=obj.get("x_mitre_platforms", []) or [],
                                 references=_external_url(obj))
                    self.software[sid] = s
                    stix_to_attack[obj["id"]] = sid
                    self._software_by_name[s.name.lower()] = sid
                    for al in s.aliases:
                        self._software_by_name[al.lower()] = sid
                    counts["software"] += 1
            elif otype == "intrusion-set":
                gid = _external_id(obj, {"mitre-attack"})
                if gid:
                    g = ATTACKGroup(group_id=gid, name=obj.get("name", ""),
                                    aliases=obj.get("aliases", []) or [],
                                    description=obj.get("description", ""),
                                    references=_external_url(obj))
                    self.groups[gid] = g
                    stix_to_attack[obj["id"]] = gid
                    self._group_by_name[g.name.lower()] = gid
                    for al in g.aliases:
                        self._group_by_name[al.lower()] = gid
                    counts["groups"] += 1
            elif otype == "relationship":
                rels.append(obj)

        counts["relationships"] = self._resolve_relationships(rels, stix_to_attack)
        return counts

    def _parse_technique(self, obj: Dict[str, Any]) -> Optional[Technique]:
        tid = _external_id(obj, {"mitre-attack"})
        if not tid:
            return None
        return Technique(
            technique_id=tid, name=obj.get("name", ""),
            description=obj.get("description", ""),
            tactics=_tactics_of(obj), domain=self.domain,
            platforms=obj.get("x_mitre_platforms", []) or [],
            data_sources=obj.get("x_mitre_data_sources", []) or [],
            detection=obj.get("x_mitre_detection", ""),
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
            references=_external_url(obj))

    def _resolve_relationships(self, rels: List[Dict[str, Any]],
                               stix_to_attack: Dict[str, str]) -> int:
        n = 0
        for rel in rels:
            rtype = rel.get("relationship_type")
            src = stix_to_attack.get(rel.get("source_ref", ""))
            dst = stix_to_attack.get(rel.get("target_ref", ""))
            if not src or not dst:
                continue
            if rtype == "uses":
                if src in self.groups and dst in self.techniques:
                    self.groups[src].techniques.append(dst)
                    n += 1
                elif src in self.groups and dst in self.software:
                    self.groups[src].software.append(dst)
                    n += 1
                elif src in self.software and dst in self.techniques:
                    self.software[src].techniques.append(dst)
                    if src not in self.techniques.get(dst, Technique("")).__dict__.get(
                            "software", []):
                        pass
                    n += 1
            elif rtype == "mitigates":
                if src in self.mitigations and dst in self.techniques:
                    self.mitigations[src].techniques.append(dst)
                    self.techniques[dst].mitigations.append(src)
                    n += 1
            elif rtype == "subtechnique-of":
                if src in self.techniques and dst in self.techniques:
                    self.techniques[src].is_subtechnique = True
                    self.techniques[src].parent_id = dst
                    n += 1
        # de-dup accumulated lists
        for g in self.groups.values():
            g.techniques = sorted(set(g.techniques))
            g.software = sorted(set(g.software))
        for s in self.software.values():
            s.techniques = sorted(set(s.techniques))
        for m in self.mitigations.values():
            m.techniques = sorted(set(m.techniques))
        for t in self.techniques.values():
            t.mitigations = sorted(set(t.mitigations))
        return n

    def load_stix_json(self, text: str) -> Dict[str, int]:
        return self.load_stix_bundle(json.loads(text))

    # -- lookups ----------------------------------------------------------- #

    def technique(self, tid: str) -> Optional[Technique]:
        return self.techniques.get(normalize_technique_id(tid) or (tid or "").upper())

    def resolve_technique(self, name_or_id: str) -> Optional[Technique]:
        nid = normalize_technique_id(name_or_id)
        if nid and nid in self.techniques:
            return self.techniques[nid]
        by_name = self._tech_by_name.get((name_or_id or "").strip().lower())
        return self.techniques.get(by_name) if by_name else None

    def tactic(self, tid: str) -> Optional[Tactic]:
        return self.tactics.get((tid or "").upper())

    def mitigation(self, mid: str) -> Optional[Mitigation]:
        return self.mitigations.get((mid or "").upper())

    def group(self, gid: str) -> Optional[ATTACKGroup]:
        return self.groups.get((gid or "").upper())

    def resolve_group(self, name_or_id: str) -> Optional[ATTACKGroup]:
        key = (name_or_id or "").strip()
        if key.upper() in self.groups:
            return self.groups[key.upper()]
        gid = self._group_by_name.get(key.lower())
        return self.groups.get(gid) if gid else None

    def resolve_software(self, name_or_id: str) -> Optional[Software]:
        key = (name_or_id or "").strip()
        if key.upper() in self.software:
            return self.software[key.upper()]
        sid = self._software_by_name.get(key.lower())
        return self.software.get(sid) if sid else None

    def techniques_for_group(self, name_or_id: str) -> List[Technique]:
        g = self.resolve_group(name_or_id)
        if not g:
            return []
        return [self.techniques[t] for t in g.techniques if t in self.techniques]

    def techniques_for_software(self, name_or_id: str) -> List[Technique]:
        s = self.resolve_software(name_or_id)
        if not s:
            return []
        return [self.techniques[t] for t in s.techniques if t in self.techniques]

    def mitigations_for(self, tid: str) -> List[Mitigation]:
        t = self.technique(tid)
        if not t:
            return []
        return [self.mitigations[m] for m in t.mitigations if m in self.mitigations]

    def tactics_ordered(self) -> List[Tactic]:
        return sorted(self.tactics.values(), key=lambda t: t.order)

    def coverage_matrix(self, technique_ids: List[str]) -> Dict[str, List[str]]:
        """Group a set of observed technique ids by tactic (kill-chain columns)."""
        matrix: Dict[str, List[str]] = {short: [] for _, short, _ in ENTERPRISE_TACTICS}
        for tid in technique_ids:
            t = self.technique(tid)
            if not t:
                continue
            for tac in (t.tactics or ["unknown"]):
                matrix.setdefault(tac, []).append(t.technique_id)
        return {k: sorted(set(v)) for k, v in matrix.items() if v}

    def stats(self) -> Dict[str, int]:
        return {"techniques": len(self.techniques), "tactics": len(self.tactics),
                "mitigations": len(self.mitigations), "software": len(self.software),
                "groups": len(self.groups)}

    # -- built-in offline seed -------------------------------------------- #

    def load_seed(self) -> "ATTACKEngine":
        """Load a compact, coherent slice of ATT&CK for offline use/tests."""
        seed_techniques = [
            ("T1566", "Phishing", ["initial-access"], False, ""),
            ("T1566.001", "Spearphishing Attachment", ["initial-access"], True, "T1566"),
            ("T1566.002", "Spearphishing Link", ["initial-access"], True, "T1566"),
            ("T1059", "Command and Scripting Interpreter", ["execution"], False, ""),
            ("T1059.001", "PowerShell", ["execution"], True, "T1059"),
            ("T1059.003", "Windows Command Shell", ["execution"], True, "T1059"),
            ("T1547", "Boot or Logon Autostart Execution", ["persistence",
                                                            "privilege-escalation"], False, ""),
            ("T1055", "Process Injection", ["defense-evasion",
                                            "privilege-escalation"], False, ""),
            ("T1027", "Obfuscated Files or Information", ["defense-evasion"], False, ""),
            ("T1003", "OS Credential Dumping", ["credential-access"], False, ""),
            ("T1082", "System Information Discovery", ["discovery"], False, ""),
            ("T1021", "Remote Services", ["lateral-movement"], False, ""),
            ("T1071", "Application Layer Protocol", ["command-and-control"], False, ""),
            ("T1071.001", "Web Protocols", ["command-and-control"], True, "T1071"),
            ("T1041", "Exfiltration Over C2 Channel", ["exfiltration"], False, ""),
            ("T1486", "Data Encrypted for Impact", ["impact"], False, ""),
            ("T1490", "Inhibit System Recovery", ["impact"], False, ""),
        ]
        for tid, name, tactics, is_sub, parent in seed_techniques:
            self.techniques[tid] = Technique(
                technique_id=tid, name=name, tactics=tactics,
                domain=ATTACKDomain.ENTERPRISE, is_subtechnique=is_sub,
                parent_id=parent, references=[f"https://attack.mitre.org/techniques/"
                                              f"{tid.replace('.', '/')}/"])
            self._tech_by_name[name.lower()] = tid
        seed_mitigations = [
            ("M1049", "Antivirus/Antimalware", ["T1566.001", "T1027", "T1486"]),
            ("M1017", "User Training", ["T1566", "T1566.001", "T1566.002"]),
            ("M1040", "Behavior Prevention on Endpoint", ["T1055", "T1059.001"]),
            ("M1053", "Data Backup", ["T1486", "T1490"]),
        ]
        for mid, name, techs in seed_mitigations:
            self.mitigations[mid] = Mitigation(mitigation_id=mid, name=name,
                                               techniques=techs)
            for t in techs:
                if t in self.techniques:
                    self.techniques[t].mitigations.append(mid)
        for t in self.techniques.values():
            t.mitigations = sorted(set(t.mitigations))
        return self


__all__ = ["ATTACKEngine", "ATTACKGroup"]
