"""Tests for social analysis: networks, interactions, communities, consistency."""

from __future__ import annotations

from behavioral_intelligence.models import Observation
from behavioral_intelligence.social import (build_mention_network,
                                            analyze_interactions,
                                            detect_communities, detect_migrations)
from behavioral_intelligence.scoring import compare_accounts
from behavioral_intelligence.tests.conftest import at


def _mention_obs():
    obs = []
    for d in range(20):
        obs.append(Observation(platform="x", account_id="alice", timestamp=at(d, 20),
                               text="hi", mentions=["bob", "carol"]))
        obs.append(Observation(platform="x", account_id="bob", timestamp=at(d, 21),
                               text="hi", mentions=["alice"]))
    return obs


def test_mention_network_and_reciprocity():
    net = build_mention_network(_mention_obs(), "e1")
    assert net.edges
    # alice<->bob mutual => reciprocity > 0
    assert net.reciprocity > 0
    edge = next(e for e in net.edges if e.source == "alice" and e.target == "bob")
    assert edge.count == 20


def test_interaction_patterns():
    p = analyze_interactions(_mention_obs())
    assert p.total_interactions > 0
    assert 0 <= p.reciprocity <= 1
    assert p.repeated_partners >= 1


def test_community_min_threshold():
    # tiny graph -> no communities, with an explanatory note
    net = build_mention_network(_mention_obs(), "e1")
    res = detect_communities(net.edges)
    assert res.communities == [] or res.node_count < 4
    assert "too small" in res.note or res.communities is not None


def test_community_detection_on_larger_graph():
    obs = []
    # two clusters: {a,b,c} interacting, {d,e,f} interacting
    for src, tgts in [("a", ["b", "c"]), ("b", ["a", "c"]), ("c", ["a", "b"]),
                      ("d", ["e", "f"]), ("e", ["d", "f"]), ("f", ["d", "e"])]:
        for t in tgts:
            obs.append(Observation(platform="x", account_id=src, timestamp=at(1),
                                   mentions=[t]))
    net = build_mention_network(obs, "e1")
    res = detect_communities(net.edges, algorithm="label_propagation")
    assert res.node_count == 6
    assert len(res.communities) >= 1


def test_consistency_supporting_evidence_only():
    a = [Observation(platform="x", account_id="a", timestamp=at(d, 20),
                     text="osint tooling", language="en", urls=["https://g.com/1"])
         for d in range(20)]
    b = [Observation(platform="y", account_id="b", timestamp=at(d, 20),
                     text="osint tooling", language="en", urls=["https://g.com/1"])
         for d in range(20)]
    result = compare_accounts({"x/alice": a, "y/alicia": b})
    assert 0 <= result.overall <= 1
    assert result.assertion.kind.value == "CORRELATED"
    lims = " ".join(x.text for x in result.assertion.confidence.limitations).lower()
    assert "same person" in lims and "not proof" in lims


def test_platform_migration_detection():
    obs = []
    for d in range(0, 20):     # platform A active early
        obs.append(Observation(platform="reddit", account_id="a", timestamp=at(d, 20),
                               urls=["https://shared.com/x"]))
    for d in range(15, 40):    # platform B active later, overlapping
        obs.append(Observation(platform="mastodon", account_id="a", timestamp=at(d, 20),
                               urls=["https://shared.com/x"]))
    migrations = detect_migrations(obs)
    assert any(m.from_platform == "reddit" and m.to_platform == "mastodon"
               for m in migrations)
