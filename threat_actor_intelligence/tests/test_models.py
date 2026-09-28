"""Model layer: IOC normalization, evidence/confidence, entities, round-trips."""
from __future__ import annotations

import time
import pytest

from threat_actor_intelligence.models import (
    IOC, IOCType, canonicalize, detect_type, CanonicalizeError,
    ThreatActor, ActorType, Alias, Campaign, MalwareFamily, Infrastructure,
    InfraType, Report, EvidenceRef, EvidenceBundle, confidence_from_evidence,
    Relationship, Technique, normalize_technique_id, VictimObservation)


@pytest.mark.parametrize("raw,expected_type,expected_val", [
    ("hxxps://evil[.]com/x", IOCType.URL, None),
    ("Evil.Example.COM", IOCType.DOMAIN, "evil.example.com"),
    ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5, "44d88612fea8a8f36de82e1278abb02f"),
    ("AS13335", IOCType.ASN, "AS13335"),
    ("1.2.3.4", IOCType.IP, "1.2.3.4"),
])
def test_ioc_detect_and_canonicalize(raw, expected_type, expected_val):
    t = detect_type(raw)
    assert t == expected_type
    val = canonicalize(t, raw)
    if expected_val is not None:
        assert val == expected_val


def test_ioc_defang_roundtrip():
    ioc = IOC.parse("evil.example.ru")
    d = ioc.to_dict()
    ioc2 = IOC.from_dict(d)
    assert ioc2.id == ioc.id
    assert ioc2.value == "evil.example.ru"


def test_ioc_invalid_domain_raises():
    with pytest.raises(CanonicalizeError):
        canonicalize(IOCType.DOMAIN, "not a domain at all")


def test_ioc_dedup_same_id():
    a = IOC(IOCType.DOMAIN, "evil.com")
    b = IOC(IOCType.DOMAIN, "evil.com")
    assert a.id == b.id


def test_evidence_bundle_dedup_and_weight():
    b = EvidenceBundle()
    ref = EvidenceRef(provider="cisa", source_class="government",
                      title="Adv", external_id="X1")
    assert b.add(ref) is True
    assert b.add(EvidenceRef(provider="cisa", source_class="government",
                             title="Adv", external_id="X1")) is False
    assert len(b) == 1
    assert 0.9 <= ref.weight <= 1.0


def test_confidence_from_evidence_corroboration(now):
    b = EvidenceBundle()
    b.add(EvidenceRef(provider="cisa", source_class="government", observed_at=now))
    single = confidence_from_evidence(b, now=now)
    b.add(EvidenceRef(provider="mandiant", source_class="vendor", observed_at=now))
    double = confidence_from_evidence(b, now=now)
    assert double.score >= single.score
    assert double.band in ("moderate", "high", "very high")
    # standing CTI limitations always present
    texts = " ".join(l.text for l in double.limitations)
    assert "Aliases" in texts and "attribution" in texts


def test_actor_roundtrip_and_confidence(now):
    a = ThreatActor("APT29", actor_type="nation-state")
    a.add_alias(Alias("Cozy Bear", "crowdstrike"))
    a.evidence.add(EvidenceRef(provider="cisa", source_class="government",
                               observed_at=now))
    a.recompute_confidence(now=now)
    assert a.actor_id == "apt29"
    assert "cozy bear" in a.all_names()
    a2 = ThreatActor.from_dict(a.to_dict())
    assert a2.to_dict() == a.to_dict()


def test_actor_alias_not_duplicated():
    a = ThreatActor("APT29")
    assert a.add_alias(Alias("Cozy Bear")) is True
    assert a.add_alias(Alias("cozy bear")) is False


def test_malware_hash_reference_only():
    m = MalwareFamily("SUNBURST", category="backdoor")
    m.add_hash("A" * 64)
    m.add_hash("a" * 64)   # same, lowercased
    assert m.known_hashes == ["a" * 64]


def test_infrastructure_overlap_keys():
    n = Infrastructure(InfraType.DOMAIN, "a.com", asn="AS1", certificates=["c1"])
    keys = n.overlap_keys()
    assert "asn:AS1" in keys and "cert:c1" in keys


def test_technique_subtechnique_parent():
    t = Technique("T1059.001", name="PowerShell", tactics=["execution"])
    assert t.is_subtechnique and t.parent_id == "T1059"
    assert normalize_technique_id("t1059.001") == "T1059.001"
    assert normalize_technique_id("nope") == ""


def test_victim_sector_normalization():
    v = VictimObservation(country="us", industry="Central Bank")
    assert v.country == "US"
    assert v.sector == "financial"


def test_relationship_id_deterministic():
    r1 = Relationship("actor", "apt29", "uses", "malware", "mal-x")
    r2 = Relationship("actor", "apt29", "uses", "malware", "mal-x")
    assert r1.id == r2.id
