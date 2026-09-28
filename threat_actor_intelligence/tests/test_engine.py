"""Public engine API + Telegram command service + scheduler."""
from __future__ import annotations

import json
import pytest

from threat_actor_intelligence.ingestion import STIXIngestor, OTXIngestor
from threat_actor_intelligence.telegram.commands import TAICommandService
from threat_actor_intelligence.telegram.callbacks import dispatch
from threat_actor_intelligence.scheduler import IngestionScheduler


@pytest.fixture
def loaded(orchestrator, engine, stix_bundle, otx_json):
    orchestrator.ingest_result(STIXIngestor().parse(stix_bundle))
    orchestrator.ingest_result(OTXIngestor().parse(otx_json))
    orchestrator.correlate()
    return engine


def test_engine_actor_report(loaded):
    d = loaded.actor_report("APT29")
    assert d["identity"]["canonical_name"] == "APT29"
    assert loaded.actor_report("APT29", fmt="markdown").startswith("# ")


def test_engine_resolve_by_alias(loaded):
    a = loaded.resolve_actor("Cozy Bear")
    assert a and a.actor_id == "apt29"


def test_engine_ioc_lookup(loaded):
    assert loaded.lookup_ioc("evil.example.com") is not None
    assert loaded.lookup_ioc("nonexistent-nowhere.zzz") is None


def test_engine_technique_and_capec(loaded):
    t = loaded.technique("T1566")
    assert t["technique"]["name"] == "Phishing"
    assert t["capec"]
    assert loaded.capec_pattern("CAPEC-98")["name"] == "Phishing"


def test_engine_timeline_and_graphs(loaded):
    assert loaded.timeline("APT29")["event_count"] >= 1
    g = json.loads(loaded.actor_graph("APT29"))
    assert g["stats"]["nodes"] >= 1
    assert "digraph" in loaded.actor_graph("APT29", fmt="dot")
    assert loaded.mitre_graph("APT29") is not None


def test_engine_corroborations_and_overlaps(loaded):
    assert isinstance(loaded.corroborations(), list)
    assert "relationships" in loaded.infrastructure_overlaps()


def test_command_service(loaded, config):
    svc = TAICommandService(config=config, engine=loaded)
    assert "APT29" in svc.cmd_actor(["APT29"])
    assert "Usage" in svc.cmd_actor([])
    assert "SUNBURST" in svc.cmd_malware(["SUNBURST"]) or "No malware" in svc.cmd_malware(["SUNBURST"])
    assert "Phishing" in svc.cmd_attack(["T1566"])
    assert "CAPEC-98" in svc.cmd_capec(["98"])
    assert "Timeline" in svc.cmd_timeline(["APT29"])


def test_callback_dispatch(loaded, config):
    svc = TAICommandService(config=config, engine=loaded)
    assert "digraph" in dispatch("graph", "apt29", service=svc)
    assert "Malware" in dispatch("malware", "apt29", service=svc)


def test_scheduler_due_logic(orchestrator, config):
    sched = IngestionScheduler(orchestrator, config=config)
    # nothing has run yet -> all available providers due
    due = sched.due_providers(now=1e9)
    assert isinstance(due, list)
    status = sched.status()
    assert status["runs"] == 0 and "interval_seconds" in status
