"""
news_intelligence.graph — provenance-carrying relationship graphs + exporters.

Every edge records the article ids and signals that justify it; exports to
JSON / GraphML / GEXF / DOT with stdlib only.
"""
from .base import GraphNode, GraphEdge, NewsGraph, BaseGraphBuilder
from .news_graph import NewsGraphBuilder
from .actor_graph import ActorGraphBuilder
from .campaign_graph import CampaignGraphBuilder
from .topic_graph import TopicGraphBuilder

__all__ = ["GraphNode", "GraphEdge", "NewsGraph", "BaseGraphBuilder",
           "NewsGraphBuilder", "ActorGraphBuilder", "CampaignGraphBuilder",
           "TopicGraphBuilder"]
