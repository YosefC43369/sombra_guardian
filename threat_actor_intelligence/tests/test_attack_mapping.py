"""MITRE ATT&CK / CAPEC: bundle load, mapping, tactic coverage, software match."""
from __future__ import annotations

import pytest

from threat_actor_intelligence.mitre import (
    ATTACKEngine, CAPECEngine, TechniqueMapper, TacticMapper, SoftwareMapper)
from threat_actor_intelligence.models.malware_family import MalwareFamily


def test_seed_loads(attack):
    s = attack.stats()
    assert s["techniques"] >= 15 and s["tactics"] == 14


def test_stix_bundle_resolves_group_and_software():
    bundle = {"type": "bundle", "objects": [
        {"type": "attack-pattern", "id": "ap--1", "name": "PowerShell",
         "external_references": [{"source_name": "mitre-attack",
                                  "external_id": "T1059.001"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                "phase_name": "execution"}],
         "x_mitre_is_subtechnique": True},
        {"type": "intrusion-set", "id": "is--1", "name": "APT29",
         "aliases": ["Cozy Bear"],
         "external_references": [{"source_name": "mitre-attack",
                                  "external_id": "G0016"}]},
        {"type": "malware", "id": "mal--1", "name": "SUNBURST",
         "external_references": [{"source_name": "mitre-attack",
                                  "external_id": "S0559"}]},
        {"type": "relationship", "id": "r1", "relationship_type": "uses",
         "source_ref": "is--1", "target_ref": "ap--1"},
        {"type": "relationship", "id": "r2", "relationship_type": "uses",
         "source_ref": "mal--1", "target_ref": "ap--1"},
    ]}
    a = ATTACKEngine()
    counts = a.load_stix_bundle(bundle)
    assert counts["techniques"] == 1 and counts["groups"] == 1
    assert [t.technique_id for t in a.techniques_for_group("Cozy Bear")] == ["T1059.001"]
    assert [t.technique_id for t in a.techniques_for_software("SUNBURST")] == ["T1059.001"]


def test_technique_mapper_text(attack):
    tm = TechniqueMapper(attack)
    hits = tm.map_text("Actor used spearphishing attachment then PowerShell (T1027).")
    ids = {h.technique_id for h in hits}
    assert "T1566.001" in ids   # keyword
    assert "T1059.001" in ids   # keyword
    assert "T1027" in ids       # explicit


def test_tactic_coverage(attack):
    tac = TacticMapper(attack)
    summary = tac.summary(["T1566", "T1059.001", "T1486"])
    assert summary["tactics_covered"] >= 3
    assert 0 < summary["coverage_score"] <= 1


def test_capec_seed_mapping(capec):
    patterns = capec.patterns_for_technique("T1566")
    assert any(p.capec_id == "CAPEC-98" for p in patterns)


def test_capec_stix_parse():
    c = CAPECEngine()
    c.load_objects([{"name": "Phishing", "external_references": [
        {"source_name": "capec", "external_id": "CAPEC-98"},
        {"source_name": "mitre-attack", "external_id": "T1566"},
        {"source_name": "cwe", "external_id": "CWE-451"}]}])
    assert c.get("CAPEC-98").related_techniques == ["T1566"]


def test_software_mapper_exact_only():
    bundle = {"type": "bundle", "objects": [
        {"type": "malware", "id": "m--1", "name": "SUNBURST",
         "x_mitre_aliases": ["Solorigate"],
         "external_references": [{"source_name": "mitre-attack",
                                  "external_id": "S0559"}]}]}
    a = ATTACKEngine()
    a.load_stix_bundle(bundle)
    sm = SoftwareMapper(a)
    fam = MalwareFamily("Solorigate")   # alias match
    m = sm.enrich(fam)
    assert m and fam.attack_software_id == "S0559"
    # a non-matching family gets nothing
    assert sm.match(MalwareFamily("TotallyUnknownThing")) is None
