"""Tests for the entity extraction facade + individual extractors."""
from news_intelligence.extraction import EntityExtractor
from news_intelligence.extraction.ioc_extractor import IOCExtractor
from news_intelligence.extraction.cve_extractor import CVEExtractor
from news_intelligence.extraction.actor_extractor import ActorExtractor
from news_intelligence.extraction.malware_extractor import MalwareExtractor
from news_intelligence.extraction.location_extractor import LocationExtractor
from news_intelligence.extraction.organization_extractor import OrganizationExtractor
from news_intelligence.extraction.mitre_extractor import MitreExtractor
from news_intelligence.models.entity import EntityType

TEXT = ("Microsoft observed Midnight Blizzard (APT29) exploiting CVE-2024-1234 in "
        "the wild against Ukraine. Cozy Bear deployed Cobalt Strike beacons. "
        "IOC evil[.]com, 8.8.8.8, hash 44d88612fea8a8f36de82e1278abb02f. "
        "Technique T1566.001. CISA issued an advisory. Acme Corporation was hit.")


def test_facade_extracts_all_types():
    ms = EntityExtractor().extract(TEXT)
    types = {m.entity_type for m in ms}
    for t in (EntityType.CVE, EntityType.THREAT_ACTOR, EntityType.MALWARE_FAMILY,
              EntityType.DOMAIN, EntityType.IP, EntityType.HASH,
              EntityType.ATTACK_TECHNIQUE, EntityType.COUNTRY):
        assert t in types, f"missing {t}"


def test_actor_aliases_preserved_with_canonical():
    ms = ActorExtractor().extract(TEXT)
    vals = {m.value for m in ms}
    assert "APT29" in vals
    assert "Midnight Blizzard" in vals  # alias kept separate
    assert "Cozy Bear" in vals
    for m in ms:
        if m.value in ("Midnight Blizzard", "Cozy Bear"):
            assert m.detail.get("canonical") == "APT29"


def test_ioc_extractor_defangs():
    ms = IOCExtractor().extract("visit hxxps://evil[.]com and 1.2.3.4")
    vals = {m.value for m in ms}
    assert "evil.com" in vals
    assert "1.2.3.4" in vals


def test_cve_extractor_flags_exploit_context():
    ms = CVEExtractor().extract("CVE-2024-1234 is actively exploited in the wild")
    assert ms and ms[0].detail.get("exploit_context") is True


def test_malware_extractor_dictionary():
    ms = MalwareExtractor().extract("The LockBit ransomware and Cobalt Strike beacon")
    vals = {m.value for m in ms}
    assert "LockBit" in vals
    assert "Cobalt Strike" in vals


def test_location_country_and_demonym():
    ms = LocationExtractor().extract("Attacks in Russia by Russian actors against Ukraine")
    vals = {m.value for m in ms}
    assert "Russia" in vals
    assert "Ukraine" in vals


def test_org_and_agency_split():
    ms = OrganizationExtractor().extract("CISA and Microsoft responded")
    agencies = {m.value for m in ms if m.entity_type == EntityType.GOVERNMENT_AGENCY}
    orgs = {m.value for m in ms if m.entity_type == EntityType.ORGANIZATION}
    assert "CISA" in agencies
    assert "Microsoft" in orgs


def test_mitre_extracts_technique_id():
    ms = MitreExtractor().extract("They used T1566.001 for initial access")
    assert any(m.value == "T1566.001" for m in ms)


def test_dedupe_counts_occurrences():
    ms = EntityExtractor().extract("APT29 APT29 APT29 struck again")
    apt = [m for m in ms if m.value == "APT29"]
    assert len(apt) == 1
    assert apt[0].detail.get("count", 1) >= 2
