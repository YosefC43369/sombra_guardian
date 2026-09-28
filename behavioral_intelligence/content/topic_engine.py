"""
behavioral_intelligence.content.topic_engine — lightweight topic discovery.

Without pulling in an LDA/embedding dependency, topics are discovered from the
co-occurrence structure of salient keywords: build a co-occurrence graph over the
top TF-IDF terms, then extract connected components as topic clusters, each
labelled by its highest-weight term. This is explainable (every topic is a set of
observed terms) and deterministic. No psychological or ideological interpretation
is attached — a topic is a group of words that appear together (spec §15).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Set

from ..models.observation import Observation
from ..linguistic.keyword_engine import extract_keywords, tokenize


@dataclass
class Topic:
    label: str = ""
    terms: List[str] = field(default_factory=list)
    weight: float = 0.0
    frequency: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {"label": self.label, "terms": self.terms,
                "weight": round(self.weight, 3), "frequency": self.frequency}


def discover_topics(observations: Sequence[Observation], *, max_terms: int = 40,
                    min_cooccurrence: int = 2, max_topics: int = 10) -> List[Topic]:
    keywords = extract_keywords(observations, top_n=max_terms)
    if not keywords:
        return []
    kw_by_term = {k.term: k for k in keywords}
    vocab: Set[str] = set(kw_by_term)

    # co-occurrence graph over the salient vocabulary
    edges: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for o in observations:
        present = [t for t in set(tokenize(o.text)) if t in vocab]
        for i in range(len(present)):
            for j in range(i + 1, len(present)):
                a, b = present[i], present[j]
                edges[a][b] += 1
                edges[b][a] += 1

    # connected components using edges above the threshold
    adj: Dict[str, Set[str]] = defaultdict(set)
    for a, nbrs in edges.items():
        for b, w in nbrs.items():
            if w >= min_cooccurrence:
                adj[a].add(b)
                adj[b].add(a)

    seen: Set[str] = set()
    topics: List[Topic] = []
    for term in sorted(vocab, key=lambda t: kw_by_term[t].tfidf, reverse=True):
        if term in seen:
            continue
        # BFS component
        comp: Set[str] = set()
        stack = [term]
        while stack:
            cur = stack.pop()
            if cur in comp:
                continue
            comp.add(cur)
            seen.add(cur)
            stack.extend(adj.get(cur, set()) - comp)
        terms_sorted = sorted(comp, key=lambda t: kw_by_term[t].tfidf, reverse=True)
        weight = sum(kw_by_term[t].tfidf for t in comp)
        freq = sum(kw_by_term[t].frequency for t in comp)
        topics.append(Topic(label=terms_sorted[0], terms=terms_sorted[:8],
                            weight=weight, frequency=freq))
    topics.sort(key=lambda t: t.weight, reverse=True)
    return topics[:max_topics]
