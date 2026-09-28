"""
news_intelligence.graph.actor_graph — actor-centric ego graph.

Builds the neighbourhood of one threat actor: the malware, CVEs, campaigns,
countries and techniques reported alongside it, with article-id provenance on every
edge. Vendor aliases are added as alias nodes linked to the actor (reported-as,
never merged).
"""
from __future__ import annotations
from typing import List, Optional
from ..models.article import Article
from ..models.actor import normalize_actor_name
from ..extraction.reference import actor_aliases_for
from .base import NewsGraph, BaseGraphBuilder


class ActorGraphBuilder(BaseGraphBuilder):
    def build(self, actor: str, articles: List[Article]) -> NewsGraph:
        actor = normalize_actor_name(actor)
        g = NewsGraph(f"actor:{actor}")
        anode = f"actor:{actor.lower()}"
        g.add_node(anode, "actor", label=actor)
        for alias in actor_aliases_for(actor):
            an = f"alias:{alias.lower()}"
            g.add_node(an, "alias", label=alias)
            g.add_edge(anode, an, "reported_as")
        for a in articles:
            if a.duplicate_of:
                continue
            if actor.lower() not in {x.lower() for x in a.actor_mentions}:
                continue
            aid = a.article_id
            for mal in a.malware_mentions:
                g.add_node(f"malware:{mal.lower()}", "malware", label=mal)
                g.add_edge(anode, f"malware:{mal.lower()}", "uses_malware",
                           article_ids=[aid])
            for cve in a.cve_mentions:
                g.add_node(f"cve:{cve.lower()}", "cve", label=cve)
                g.add_edge(anode, f"cve:{cve.lower()}", "linked_cve",
                           article_ids=[aid])
            for c in a.country_mentions:
                g.add_node(f"country:{c.lower()}", "country", label=c)
                g.add_edge(anode, f"country:{c.lower()}", "linked_country",
                           article_ids=[aid])
            for t in a.mitre_techniques:
                g.add_node(f"technique:{t.lower()}", "technique", label=t)
                g.add_edge(anode, f"technique:{t.lower()}", "uses_technique",
                           article_ids=[aid])
        return g


__all__ = ["ActorGraphBuilder"]
