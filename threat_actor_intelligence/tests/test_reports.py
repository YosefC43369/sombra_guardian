"""Report generation: dossiers + markdown/html/json/csv renderers."""
from __future__ import annotations

import json
import pytest

from threat_actor_intelligence.ingestion import STIXIngestor, OTXIngestor
from threat_actor_intelligence.reports import (
    ActorReportBuilder, CampaignReportBuilder, MalwareReportBuilder,
    render_report, markdown_report, html_report, json_report, csv_report)


@pytest.fixture
def populated(orchestrator, store, stix_bundle, otx_json):
    orchestrator.ingest_result(STIXIngestor().parse(stix_bundle))
    orchestrator.ingest_result(OTXIngestor().parse(otx_json))
    orchestrator.correlate()
    return store


def test_actor_dossier_sections(populated, attack):
    d = ActorReportBuilder(populated, attack=attack).build("apt29")
    for section in ("executive_summary", "aliases", "campaign_timeline",
                    "malware_relationships", "attack_coverage", "infrastructure",
                    "victimology", "public_reports", "evidence", "confidence",
                    "limitations"):
        assert section in d
    assert d["identity"]["canonical_name"] == "APT29"
    # limitations always include the aliases-not-identity guard
    texts = " ".join(l["text"] for l in d["limitations"])
    assert "alias" in texts.lower()


def test_actor_markdown_render(populated, attack):
    d = ActorReportBuilder(populated, attack=attack).build("apt29")
    md = markdown_report.render(d)
    assert "# Threat Actor Dossier" in md
    assert "Limitations" in md and "Confidence" in md
    assert "Cozy Bear" in md


def test_actor_html_render(populated, attack):
    d = ActorReportBuilder(populated, attack=attack).build("apt29")
    html = html_report.render(d)
    assert html.startswith("<!doctype html>")
    assert "<h1>" in html and "APT29" in html


def test_json_and_csv(populated, attack):
    d = ActorReportBuilder(populated, attack=attack).build("apt29")
    j = json.loads(json_report.render(d))
    assert j["kind"] == "actor"
    csv_out = csv_report.render(d)
    assert "provider" in csv_out.splitlines()[0]
    allcsv = csv_report.render_all(d)
    assert "evidence" in allcsv and "aliases" in allcsv


def test_campaign_and_malware_reports(populated, attack):
    cd = CampaignReportBuilder(populated, attack=attack).build(
        "camp-solarwinds-compromise")
    assert cd and cd["kind"] == "campaign"
    md = MalwareReportBuilder(populated, attack=attack).build("mal-sunburst")
    assert md and md["kind"] == "malware"
    assert "no sample bytes" in md["known_hashes"]["note"].lower()


def test_render_report_dispatch(populated, attack):
    d = ActorReportBuilder(populated, attack=attack).build("apt29")
    assert render_report(d, fmt="markdown").startswith("# ")
    with pytest.raises(ValueError):
        render_report(d, fmt="bogus")
