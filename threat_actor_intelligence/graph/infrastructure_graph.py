"""
threat_actor_intelligence.graph.infrastructure_graph — infrastructure overlap graph.

Draws infrastructure nodes and the overlap edges between them (shared cert/IP/
ASN/domain), optionally pulling in the campaigns/actors each node is tied to, so a
shared-certificate cluster spanning two campaigns is visible at a glance.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..models.infrastructure import Infrastructure
from ..models.relation import Relationship
from .base import CTIGraph


class InfrastructureGraphBuilder:
    def build(self, nodes: Sequence[Infrastructure], *,
              overlap_relationships: Optional[Sequence[Relationship]] = None,
              labels: Optional[Dict[str, str]] = None) -> CTIGraph:
        g = CTIGraph(name="infrastructure")
        labels = dict(labels or {})
        for node in nodes:
            g.add_node(node.infra_id, "infrastructure", node.value,
                       infra_type=node.infra_type.value, asn=node.asn,
                       country=node.country)
            for cid in node.campaigns:
                g.add_node(cid, "campaign", labels.get(cid, cid))
                g.add_edge(cid, node.infra_id, "uses", signal="campaign infra",
                           weight=0.6)
            for aid in node.actors:
                g.add_node(aid, "actor", labels.get(aid, aid))
                g.add_edge(aid, node.infra_id, "uses", signal="actor infra",
                           weight=0.6)
        for rel in (overlap_relationships or []):
            g.add_relationship(rel, labels=labels)
        return g


__all__ = ["InfrastructureGraphBuilder"]
