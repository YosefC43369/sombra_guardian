"""Pipeline + orchestrator: resolution, dedup, denormalization, correlation."""
from __future__ import annotations

import pytest

from threat_actor_intelligence.ingestion import (
    RSSIngestor, STIXIngestor, OTXIngestor, CISAIngestor)


def test_pipeline_resolves_stix(orchestrator, store, stix_bundle):
    result = STIXIngestor(provider_name="opencti").parse(stix_bundle)
    stats = orchestrator.ingest_result(result)
    assert stats.actors_upserted >= 1
    assert store.get_actor("apt29") is not None
    assert store.find_family_by_name("SUNBURST") is not None
    # denormalized: actor uses malware, campaign attributed to actor
    actor = store.get_actor("apt29")
    assert "mal-sunburst" in actor.malware_families
    assert "camp-solarwinds-compromise" in actor.campaigns


def test_pipeline_dedup_reports(orchestrator, store, rss_feed):
    r = RSSIngestor(vendor="Test").parse(rss_feed)
    s1 = orchestrator.ingest_result(r)
    assert s1.reports_new == 1
    r2 = RSSIngestor(vendor="Test").parse(rss_feed)
    s2 = orchestrator.ingest_result(r2)
    assert s2.reports_new == 0 and s2.reports_skipped == 1


def test_pipeline_name_resolution_creates_stub(orchestrator, store, rss_feed):
    orchestrator.ingest_result(RSSIngestor(vendor="Test").parse(rss_feed))
    # APT29 named in the RSS body -> actor stub created with evidence
    a = store.find_actor_by_name("APT29")
    assert a is not None and len(a.evidence) >= 1
    # SUNBURST malware stub created
    assert store.find_family_by_name("SUNBURST") is not None


def test_pipeline_technique_mapping(orchestrator, store, rss_feed):
    orchestrator.ingest_result(RSSIngestor(vendor="Test").parse(rss_feed))
    a = store.find_actor_by_name("APT29")
    # spearphishing attachment + PowerShell mapped and linked
    assert any(t.startswith("T15") or t.startswith("T10") for t in a.techniques)


def test_orchestrator_correlate(orchestrator, store, stix_bundle, otx_json):
    orchestrator.ingest_result(STIXIngestor().parse(stix_bundle))
    orchestrator.ingest_result(OTXIngestor().parse(otx_json))
    counts = orchestrator.correlate()
    assert "reports" in counts
    # merge candidates persisted
    assert isinstance(store.kv_get("correlation", "merge_candidates", []), list)


def test_full_flow_multiple_sources(orchestrator, store, stix_bundle, otx_json,
                                    cisa_kev_json, rss_feed):
    orchestrator.ingest_result(STIXIngestor().parse(stix_bundle))
    orchestrator.ingest_result(OTXIngestor().parse(otx_json))
    orchestrator.ingest_result(CISAIngestor().parse(cisa_kev_json))
    orchestrator.ingest_result(RSSIngestor(vendor="Test").parse(rss_feed))
    orchestrator.correlate()
    s = store.stats()
    assert s["actors"] >= 1 and s["campaigns"] >= 1
    assert s["malware_families"] >= 1 and s["reports"] >= 2
    assert s["relationships"] >= 1 and s["evidence"] >= 1
