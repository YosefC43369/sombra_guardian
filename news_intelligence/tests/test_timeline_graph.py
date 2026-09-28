"""Tests for timeline builders and graph builders/exporters."""
import json
from news_intelligence.timeline.news_timeline import NewsTimelineBuilder
from news_intelligence.timeline._specific import ActorTimelineBuilder
from news_intelligence.graph.news_graph import NewsGraphBuilder
from news_intelligence.graph.actor_graph import ActorGraphBuilder
from news_intelligence.graph.topic_graph import TopicGraphBuilder


def test_actor_timeline(ingested_engine):
    tl = ActorTimelineBuilder(ingested_engine.store).build("APT29")
    d = tl.to_dict()
    assert d["count"] >= 1
    assert all(e["ts"] > 0 for e in d["entries"] if e["ts"])


def test_news_graph_export(ingested_engine):
    arts = ingested_engine.store.list_articles()
    g = NewsGraphBuilder(ingested_engine.store).build(arts)
    assert g.stats()["nodes"] > 0
    data = json.loads(g.to_json())
    assert "nodes" in data and "edges" in data
    assert g.to_dot().startswith("digraph")
    assert "<graphml" in g.to_graphml()
    assert "<gexf" in g.to_gexf()


def test_actor_graph_has_aliases(ingested_engine):
    arts = ingested_engine.store.list_articles()
    g = ActorGraphBuilder(ingested_engine.store).build("APT29", arts)
    types = g.stats()["node_types"]
    assert types.get("actor", 0) >= 1


def test_topic_graph(ingested_engine):
    arts = ingested_engine.store.list_articles()
    g = TopicGraphBuilder(ingested_engine.store).build(arts)
    assert g.stats()["nodes"] >= 0
