"""
news_intelligence.graph.topic_graph — topic co-occurrence graph.

Nodes are salient entities (actors/malware/CVEs); edges connect entities discussed
together across articles, weighted by co-mention count, with article-id provenance.
Renders the "what is being discussed together" map.
"""
from __future__ import annotations
from itertools import combinations
from typing import List
from ..models.article import Article
from .base import NewsGraph, BaseGraphBuilder


class TopicGraphBuilder(BaseGraphBuilder):
    def build(self, articles: List[Article], *, min_weight: int = 1) -> NewsGraph:
        g = NewsGraph("topic_graph")
        for a in articles:
            if a.duplicate_of:
                continue
            terms = sorted(set(a.actor_mentions + a.malware_mentions
                               + a.cve_mentions))
            for t in terms:
                g.add_node(f"topic:{t.lower()}", "topic", label=t)
            for x, y in combinations(terms, 2):
                g.add_edge(f"topic:{x.lower()}", f"topic:{y.lower()}",
                           "discussed_together", article_ids=[a.article_id])
        # prune weak edges
        g.edges = [e for e in g.edges if e.weight >= min_weight]
        return g


__all__ = ["TopicGraphBuilder"]
