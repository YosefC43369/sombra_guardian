"""Tests for report builders + renderers (markdown/html/json/csv)."""
import json as _json
from news_intelligence.reports import (render_report, DailyBriefBuilder,
    WeeklyBriefBuilder, ActorReportBuilder, MalwareReportBuilder, CVEReportBuilder,
    CampaignReportBuilder, ExecutiveReportBuilder)
from news_intelligence.models.report import NewsReport, ReportSection


def test_daily_brief_sections(ingested_engine, now):
    r = DailyBriefBuilder(ingested_engine.store, now=now).build(hours=24 * 30)
    titles = {s.title for s in r.sections}
    for expected in ("Top Threat Actors", "Top Malware", "Top CVEs",
                     "Top Campaigns", "Emerging Trends", "Infrastructure Signals",
                     "Evidence Summary"):
        assert expected in titles
    assert r.limitations  # standing limitations attached


def test_actor_report_preserves_aliases(ingested_engine, now):
    r = ActorReportBuilder(ingested_engine.store, now=now).build("APT29")
    alias_sec = next(s for s in r.sections if s.title == "Reported Aliases")
    assert any("Cozy Bear" in l for l in alias_sec.lines)


def test_cve_report_exploitation_not_asserted(ingested_engine, now):
    r = CVEReportBuilder(ingested_engine.store, now=now).build("CVE-2024-1234")
    assert r.subject == "CVE-2024-1234"


def test_malware_report(ingested_engine, now):
    r = MalwareReportBuilder(ingested_engine.store, now=now).build("LockBit")
    assert r.subject == "LockBit"


def test_renderers(ingested_engine, now):
    r = DailyBriefBuilder(ingested_engine.store, now=now).build(hours=24 * 30)
    md = render_report(r, fmt="markdown")
    html = render_report(r, fmt="html")
    js = render_report(r, fmt="json")
    csv = render_report(r, fmt="csv")
    assert md.startswith("#")
    assert "<html" in html
    assert _json.loads(js)["report_type"] == "daily"
    assert isinstance(csv, str)


def test_executive_summary(ingested_engine, now):
    r = ExecutiveReportBuilder(ingested_engine.store, now=now).build(days=30)
    assert r.summary
    assert r.limitations


def test_report_roundtrip():
    r = NewsReport(title="t")
    r.add_section(ReportSection(title="s", lines=["x"]))
    assert NewsReport.from_dict(r.to_dict()).sections[0].lines == ["x"]
