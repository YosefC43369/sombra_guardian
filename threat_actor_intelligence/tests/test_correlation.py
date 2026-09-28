"""Correlation: actor/campaign/malware/infra/ioc/report + alias resolution."""
from __future__ import annotations

import pytest

from threat_actor_intelligence.models import (
    ThreatActor, Alias, Campaign, MalwareFamily, Infrastructure, InfraType,
    IOC, IOCType, Report, EvidenceRef, SourceClass)
from threat_actor_intelligence.correlation import (
    ActorCorrelator, CampaignCorrelator, MalwareCorrelator,
    InfrastructureCorrelator, IOCCorrelator, ReportCorrelator,
    AliasResolver, similarity, normalize_name)


def _ev(p, cls="vendor", now=1e9):
    return EvidenceRef(provider=p, source_class=cls, title="r", observed_at=now)


def test_alias_numeric_guard():
    # APT29 vs APT28 must NOT be a confident match (classic collision)
    score, _ = similarity("APT29", "APT28")
    assert score < 0.5
    # same alias is a full match
    assert similarity("Cozy Bear", "cozy bear")[0] == 1.0


def test_alias_resolver_never_auto_merges(now):
    a1 = ("apt29", ["APT29", "Cozy Bear"], {"mandiant"})
    a2 = ("unc2452", ["UNC2452", "Cozy Bear"], {"mandiant"})
    cands = AliasResolver().suggest([a1, a2])
    assert cands and cands[0].requires_review is True
    assert cands[0].score == 1.0   # shared exact alias


def test_actor_correlation_shared_malware(now):
    a1 = ThreatActor("APT29"); a1.link("malware_families", "mal-sunburst")
    a1.evidence.add(_ev("mandiant", now=now))
    a2 = ThreatActor("UNC2452"); a2.link("malware_families", "mal-sunburst")
    a2.evidence.add(_ev("mandiant", now=now))
    res = ActorCorrelator().correlate([a1, a2], now=now)
    assert res.relationships and res.relationships[0].rel_type.value == "overlaps"


def test_infrastructure_overlap_and_clusters(now):
    n1 = Infrastructure(InfraType.DOMAIN, "a.com", certificates=["c1"])
    n1.evidence.add(_ev("otx", "community", now))
    n2 = Infrastructure(InfraType.DOMAIN, "b.com", certificates=["c1"])
    n2.evidence.add(_ev("otx", "community", now))
    corr = InfrastructureCorrelator()
    res = corr.correlate([n1, n2], now=now)
    assert res.relationships and "cert:c1" in res.relationships[0].signal
    assert corr.clusters([n1, n2])


def test_ioc_correlation_shared_campaign(now):
    i1 = IOC(IOCType.DOMAIN, "a.com", campaign="SolarWinds")
    i1.evidence.add(_ev("urlhaus", "community", now))
    i2 = IOC(IOCType.IP, "1.2.3.4", campaign="SolarWinds")
    i2.evidence.add(_ev("urlhaus", "community", now))
    res = IOCCorrelator().correlate([i1, i2], now=now)
    assert res.relationships and "campaign" in res.relationships[0].signal


def test_malware_shared_hash_is_variant(now):
    m1 = MalwareFamily("A"); m1.add_hash("h" * 64); m1.evidence.add(_ev("mb", now=now))
    m2 = MalwareFamily("B"); m2.add_hash("h" * 64); m2.evidence.add(_ev("mb", now=now))
    res = MalwareCorrelator().correlate([m1, m2], now=now)
    assert res.relationships[0].rel_type.value == "variant_of"


def test_report_corroboration(now):
    r1 = Report("A", source="cisa"); r1.actor_ids = ["apt29"]
    r2 = Report("B", source="mandiant"); r2.actor_ids = ["apt29"]
    rc = ReportCorrelator()
    cors = rc.corroborations([r1, r2])
    assert cors[0].corroborated and cors[0].independent_sources == 2


def test_campaign_correlation(now):
    c1 = Campaign("Camp A"); c1.link("infrastructure", "infra-x")
    c1.evidence.add(_ev("v1", now=now))
    c2 = Campaign("Camp B"); c2.link("infrastructure", "infra-x")
    c2.evidence.add(_ev("v1", now=now))
    res = CampaignCorrelator().correlate([c1, c2], now=now)
    assert res.relationships and "infrastructure" in res.relationships[0].signal
