"""Tests for report rendering and the epistemic-labelling discipline."""

from __future__ import annotations

import json

from behavioral_intelligence import BehavioralEngine
from behavioral_intelligence.reports import BehavioralReportBuilder, render_report
from behavioral_intelligence.configuration import PrivacyConfig
from behavioral_intelligence.tests.conftest import make_observations
from behavioral_intelligence.models import ObservationBatch


def _profile(dev_ctx):
    eng = BehavioralEngine()
    batch = ObservationBatch(make_observations(), entity_id="actor7", label="@alice")
    return eng.analyze_entity(batch, dev_ctx)


def test_markdown_report_has_sections_and_labels(dev_ctx):
    p = _profile(dev_ctx)
    md = BehavioralReportBuilder().markdown(p)
    assert md.count("\n## ") >= 10          # the mandated sections
    assert "[OBSERVED]" in md
    # the core disclaimer must be present
    assert "no claim about the person" in md.lower() or "not the person" in md.lower()
    # OBSERVED/CORRELATED/INFERRED/UNKNOWN legend
    assert "OBSERVED" in md and "CORRELATED" in md and "INFERRED" in md


def test_json_report_valid_and_has_disclaimer(dev_ctx):
    p = _profile(dev_ctx)
    js = BehavioralReportBuilder().json(p)
    data = json.loads(js)
    assert data["schema"].startswith("behavioral-intelligence")
    assert "disclaimer" in data
    assert "psychological" in data["disclaimer"].lower()
    assert data["profile"]["entity_id"] == "actor7"


def test_csv_report_sections(dev_ctx):
    csv = BehavioralReportBuilder().csv(_profile(dev_ctx))
    assert "## assertions" in csv
    assert "kind" in csv          # epistemic column preserved


def test_html_report_self_contained(dev_ctx):
    html = BehavioralReportBuilder().html(_profile(dev_ctx))
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    assert "<svg" in html          # inline heatmap
    assert "http://" not in html.split("</head>")[0].replace("http://www.w3.org", "")


def test_privacy_masking():
    from behavioral_intelligence.reports import markdown_report
    from behavioral_intelligence.models.behavior import BehaviorProfile, InteractionNetwork, InteractionEdge
    prof = BehaviorProfile(entity_id="e", label="e")
    prof.interactions = InteractionNetwork(edges=[
        InteractionEdge(source="alice", target="bob", count=3)])
    masked = markdown_report.render(prof, privacy=PrivacyConfig(mask_account_ids=True))
    assert "acct:" in masked and "alice" not in masked


def test_render_report_dispatch(dev_ctx):
    p = _profile(dev_ctx)
    for fmt in ("markdown", "json", "csv", "html", "summary", "evidence"):
        out = render_report(p, fmt=fmt)
        assert isinstance(out, str) and out
    # unknown format falls back to markdown
    assert render_report(p, fmt="nonsense").count("## ") >= 5
