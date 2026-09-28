"""
threat_actor_intelligence.graph — relationship graphs + GraphML/GEXF/JSON/DOT export.

``CTIGraph`` is the shared graph (pure-stdlib, optional networkx); the four
builders produce the actor, campaign, infrastructure-overlap and ATT&CK-coverage
views. Every edge carries its signal + confidence, so the graph is the spatial,
explainable view of an investigation.
"""

from .base import CTIGraph, Node, Edge, TYPE_COLORS, HAVE_NETWORKX
from .actor_graph import ActorGraphBuilder
from .campaign_graph import CampaignGraphBuilder
from .infrastructure_graph import InfrastructureGraphBuilder
from .mitre_graph import MitreGraphBuilder

__all__ = ["CTIGraph", "Node", "Edge", "TYPE_COLORS", "HAVE_NETWORKX",
           "ActorGraphBuilder", "CampaignGraphBuilder",
           "InfrastructureGraphBuilder", "MitreGraphBuilder"]
