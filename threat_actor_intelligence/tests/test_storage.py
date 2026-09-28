"""Storage: persistence round-trips, indexes, migrations, incremental state."""
from __future__ import annotations

import pytest

from threat_actor_intelligence.storage.sqlite_store import SQLiteStore, SCHEMA_VERSION
from threat_actor_intelligence.models import (
    ThreatActor, Alias, Campaign, MalwareFamily, Infrastructure, InfraType,
    IOC, IOCType, Report, Relationship, EvidenceRef)


def test_schema_migration_recorded(store):
    assert store.schema_version() == SCHEMA_VERSION
    # re-init is idempotent
    store.init_db()
    assert store.schema_version() == SCHEMA_VERSION


def test_actor_persistence_and_alias_lookup(store, now):
    a = ThreatActor("APT29", actor_type="nation-state")
    a.add_alias(Alias("Cozy Bear", "crowdstrike"))
    a.evidence.add(EvidenceRef(provider="cisa", source_class="government",
                               observed_at=now))
    a.recompute_confidence(now=now)
    store.save_actor(a)
    assert store.get_actor("apt29").canonical_name == "APT29"
    assert store.find_actor_by_name("Cozy Bear").actor_id == "apt29"
    assert [x.actor_id for x in store.find_actors_by_alias("cozy bear")] == ["apt29"]


def test_actor_upsert_merges(store, now):
    a = ThreatActor("APT29")
    a.evidence.add(EvidenceRef(provider="a", observed_at=now))
    store.save_actor(a)
    a2 = store.get_actor("apt29")
    a2.add_alias(Alias("Nobelium"))
    store.save_actor(a2)
    assert "nobelium" in store.get_actor("apt29").all_names()


def test_ioc_batch_write(store, now):
    iocs = [IOC(IOCType.DOMAIN, f"evil{i}.com") for i in range(50)]
    for i in iocs:
        i.evidence.add(EvidenceRef(provider="urlhaus", observed_at=now))
    assert store.save_iocs(iocs) == 50
    assert store.find_ioc_by_value("evil7.com") is not None
    assert len(list(store.iter_iocs(ioc_type="domain"))) == 50


def test_report_dedup_by_hash(store):
    r = Report("Advisory", url="https://x/y", source="cisa")
    store.save_report(r)
    assert store.report_exists(content_hash=r.content_hash)
    assert store.report_exists(url="https://x/y")
    assert not store.report_exists(url="https://z/w")


def test_relationships_and_lookup(store):
    rel = Relationship("actor", "apt29", "uses", "malware", "mal-sunburst",
                       signal="reported")
    store.save_relationship(rel)
    got = store.relationships_for("actor", "apt29")
    assert len(got) == 1 and got[0].rel_type.value == "uses"


def test_provider_state_incremental(store):
    store.set_provider_state("cisa", "kev.json", etag='W/"abc"',
                             last_modified="Mon")
    st = store.get_provider_state("cisa", "kev.json")
    assert st["etag"] == 'W/"abc"' and st["last_modified"] == "Mon"


def test_infrastructure_and_kv(store, now):
    n = Infrastructure(InfraType.IP, "1.2.3.4", asn="AS13335")
    n.evidence.add(EvidenceRef(provider="otx", observed_at=now))
    store.save_infrastructure(n)
    assert store.find_infrastructure_by_value("1.2.3.4")[0].asn == "AS13335"
    store.kv_set("ns", "k", {"v": 1})
    assert store.kv_get("ns", "k") == {"v": 1}


def test_timeline_persistence(store, now):
    store.save_timeline_event("actor", "apt29",
                              {"event_id": "e1", "at": now, "kind": "seen",
                               "label": "x"})
    assert len(store.timeline_for("actor", "apt29")) == 1


def test_stats(store):
    s = store.stats()
    for key in ("actors", "campaigns", "ioc", "relationships", "evidence"):
        assert key in s
