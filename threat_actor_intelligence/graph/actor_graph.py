"""
threat_actor_intelligence.graph.actor_graph — actor-centric relationship graph.

Builds the neighbourhood graph around a ThreatActor: the actor, its campaigns,
malware families, infrastructure, techniques and the reports that cite it, wired
by the stored relationships plus the actor's own reference lists. This is what
``/actor_graph`` renders and what the actor report embeds.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..models.threat_actor import ThreatActor
from ..models.relation import Relationship
from .base import CTIGraph


class ActorGraphBuilder:
    def build(self, actor: ThreatActor, *,
              relationships: Optional[Sequence[Relationship]] = None,
              labels: Optional[Dict[str, str]] = None) -> CTIGraph:
        g = CTIGraph(name=f"actor:{actor.actor_id}")
        labels = dict(labels or {})
        labels.setdefault(actor.actor_id, actor.canonical_name)
        g.add_node(actor.actor_id, "actor", actor.canonical_name,
                   confidence=(actor.confidence.score if actor.confidence else 0.0),
                   actor_type=actor.actor_type.value)
        for cid in actor.campaigns:
            g.add_node(cid, "campaign", labels.get(cid, cid))
            g.add_edge(actor.actor_id, cid, "attributed_to",
                       signal="reported attribution", weight=0.7)
        for mid in actor.malware_families:
            g.add_node(mid, "malware", labels.get(mid, mid))
            g.add_edge(actor.actor_id, mid, "uses", signal="uses malware", weight=0.7)
        for iid in actor.infrastructure:
            g.add_node(iid, "infrastructure", labels.get(iid, iid))
            g.add_edge(actor.actor_id, iid, "uses", signal="uses infrastructure",
                       weight=0.6)
        for tid in actor.techniques:
            g.add_node(tid, "technique", labels.get(tid, tid))
            g.add_edge(actor.actor_id, tid, "uses", signal="documented technique",
                       weight=0.4)
        for rid in actor.report_ids:
            g.add_node(rid, "report", labels.get(rid, rid))
            g.add_edge(rid, actor.actor_id, "mentions", signal="cited in report",
                       weight=0.5)
        for rel in (relationships or []):
            g.add_relationship(rel, labels=labels)
        return g


__all__ = ["ActorGraphBuilder"]
