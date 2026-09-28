"""Timeline generation and graph creation/export."""
from __future__ import annotations

import json
import pytest

from threat_actor_intelligence.models import (
    ThreatActor, Campaign, Infrastructure, InfraType, IOC, IOCType,
    EvidenceRef, Relationship)
from threat_actor_intelligence.timeline import (
    ActivityTimelineBuilder, CampaignTimelineBuilder,
    InfrastructureTimelineBuilder, ReportTimelineBuilder)
from threat_actor_intelligence.models.report import Report
from threat_actor_intelligence.graph import (
    CTIGraph, ActorGraphBuilder, CampaignGraphBuilder,
    InfrastructureGraphBuilder, MitreGraphBuilder)


def test_activity_timeline_requires_timestamps(now):
    a = ThreatActor("APT29", first_seen=now - 1000, last_seen=now)
    a.evidence.add(EvidenceRef(provider="cisa", observed_at=now - 500))
    tl = ActivityTimelineBuilder().build(a)
    assert tl.event_count if hasattr(tl, "event_count") else True
    d = tl.to_dict()
    assert d["event_count"] >= 2
    # an event with no timestamp is dropped
    from threat_actor_intelligence.timeline.base import TimelineEvent, Timeline
    t2 = Timeline()
    assert t2.add(TimelineEvent(at=0, kind="x")) is False


def test_campaign_timeline(now):
    c = Campaign("SolarWinds", first_observed=now - 10000, last_observed=now)
    c.evidence.add(EvidenceRef(provider="mandiant", observed_at=now - 5000))
    tl = CampaignTimelineBuilder().build(c).to_dict()
    assert tl["duration_days"] > 0


def test_report_timeline_cadence():
    r1 = Report("A", source="cisa", published_at=1e9)
    r2 = Report("B", source="mandiant", published_at=1e9 + 86400 * 40)
    cadence = ReportTimelineBuilder().cadence([r1, r2])
    assert len(cadence) == 2


def test_graph_build_and_exports():
    g = CTIGraph(name="t")
    g.add_node("apt29", "actor", "APT29")
    g.add_node("mal-x", "malware", "X")
    g.add_edge("apt29", "mal-x", "uses", signal="uses", weight=0.7, confidence=0.6)
    assert g.order() == 2 and g.size() == 1
    j = json.loads(g.to_json_str())
    assert len(j["nodes"]) == 2 and len(j["edges"]) == 1
    assert "<?xml" in g.to_graphml()
    assert "<gexf" in g.to_gexf()
    assert "digraph" in g.to_dot()


def test_graph_components_and_central():
    g = CTIGraph()
    for i in range(3):
        g.add_node(f"n{i}", "ioc", f"n{i}")
    g.add_edge("n0", "n1", "associated_with")
    comps = g.components()
    assert any(len(c) == 2 for c in comps)
    assert g.central_nodes(1)[0][0] in ("n0", "n1")


def test_actor_graph_builder(now):
    a = ThreatActor("APT29")
    a.link("malware_families", "mal-sunburst")
    a.link("campaigns", "camp-solarwinds")
    g = ActorGraphBuilder().build(a)
    assert g.order() >= 3


def test_infrastructure_graph_with_overlap(now):
    n1 = Infrastructure(InfraType.DOMAIN, "a.com", certificates=["c1"])
    n2 = Infrastructure(InfraType.DOMAIN, "b.com", certificates=["c1"])
    rel = Relationship("infrastructure", n1.infra_id, "overlaps",
                       "infrastructure", n2.infra_id, signal="shared cert")
    g = InfrastructureGraphBuilder().build([n1, n2], overlap_relationships=[rel])
    assert g.size() >= 1


def test_mitre_graph(attack):
    g = MitreGraphBuilder(attack).build(subject_id="apt29", subject_type="actor",
                                        technique_ids=["T1566", "T1059.001"],
                                        subject_label="APT29")
    assert g.order() >= 3
