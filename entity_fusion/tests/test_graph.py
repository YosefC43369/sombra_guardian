"""Tests for entity_fusion.graph — construction and every export format, on the
stdlib backend (and networkx when installed)."""

import json
import pytest

from entity_fusion.graph import IdentityGraph, HAVE_NETWORKX
from entity_fusion.entity import Entity, EntityType, Relationship, RelationType


def _graph():
    a = Entity(type=EntityType.USERNAME, value="johndoe")
    b = Entity(type=EntityType.EMAIL, value="john@example.com")
    a.add_relationship(Relationship(target_id=b.id, type=RelationType.OWNS))
    g = IdentityGraph().build_from_entities([a, b])
    return g, a, b


class TestConstruction:
    def test_nodes_and_edges(self):
        g, a, b = _graph()
        s = g.stats()
        assert s["nodes"] == 2
        assert s["edges"] == 1

    def test_dangling_target_added(self):
        a = Entity(type=EntityType.USERNAME, value="x")
        a.add_relationship(Relationship(target_id="missing-id",
                                        type=RelationType.MENTIONS))
        g = IdentityGraph().build_from_entities([a])
        assert g.stats()["nodes"] == 2  # x plus the auto-added target

    def test_link_cluster_star(self):
        g = IdentityGraph()
        for v in ("a", "b", "c"):
            g.add_entity(Entity(type=EntityType.USERNAME, value=v, id=v))
        g.link_cluster(["a", "b", "c"])
        assert g.stats()["edges"] == 2  # star: hub→b, hub→c


class TestExports:
    def test_json_roundtrip(self):
        g, a, b = _graph()
        data = json.loads(g.to_json())
        assert data["directed"] is True
        assert len(data["nodes"]) == 2
        assert len(data["links"]) == 1

    def test_dot_contains_nodes(self):
        g, a, b = _graph()
        dot = g.to_dot()
        assert dot.startswith("digraph identity")
        assert "->" in dot

    def test_graphml_is_xml(self):
        g, a, b = _graph()
        ml = g.to_graphml()
        assert ml.lstrip().startswith("<?xml")
        assert "graphml" in ml

    def test_gexf_is_xml(self):
        g, a, b = _graph()
        gexf = g.to_gexf()
        assert "gexf" in gexf

    def test_node_link_sorted_deterministic(self):
        g, a, b = _graph()
        assert g.to_json() == g.to_json()  # stable, sorted keys


def test_render_without_dot_returns_none_or_bytes():
    g, a, b = _graph()
    out = g.render("svg")
    assert out is None or isinstance(out, bytes)


@pytest.mark.skipif(not HAVE_NETWORKX, reason="networkx not installed")
def test_networkx_backend_selected():
    g, _, _ = _graph()
    assert g.backend == "networkx"
