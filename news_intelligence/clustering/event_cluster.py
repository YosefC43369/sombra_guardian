"""
news_intelligence.clustering.event_cluster — multi-article → single-event clustering.

Groups articles that are about the same real-world event using the spec's signals:
shared CVE, shared malware, shared actor, shared organization, shared infrastructure,
overlapping publication window, and semantic (TF-IDF) similarity. Every cluster
records *which* signals bound it together, so the grouping is explainable and a
reviewer can see why two stories were judged the same event.

The result is promotable to a ``NewsEvent`` (with a time window and independent-source
corroboration count) by ``promote_events``.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ..models.article import Article
from ..models.topic import Cluster, ClusterKind, NewsEvent
from .similarity import TFIDF


class EventClusterer:
    def __init__(self, *, window_hours: int = 72, min_shared_signals: int = 1,
                 tfidf_threshold: float = 0.5, use_semantic: bool = True):
        self.window = window_hours * 3600
        self.min_shared_signals = min_shared_signals
        self.tfidf_threshold = tfidf_threshold
        self.use_semantic = use_semantic

    def _strong_signals(self, a: Article) -> Set[str]:
        """The high-precision binding signals (typed so a shared CVE beats a shared
        common word)."""
        sig: Set[str] = set()
        sig |= {f"cve:{c}" for c in a.cve_mentions}
        sig |= {f"actor:{x.lower()}" for x in a.actor_mentions}
        sig |= {f"malware:{x.lower()}" for x in a.malware_mentions}
        sig |= {f"ioc:{x.lower()}" for x in a.iocs}
        sig |= {f"org:{x.lower()}" for x in a.organization_mentions}
        return sig

    def cluster(self, articles: List[Article]) -> List[Cluster]:
        articles = [a for a in articles if not a.duplicate_of]
        n = len(articles)
        parent = list(range(n))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x, y):
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[max(rx, ry)] = min(rx, ry)

        signals = [self._strong_signals(a) for a in articles]
        edge_signals: Dict[Tuple[int, int], List[str]] = defaultdict(list)

        for i in range(n):
            for j in range(i + 1, n):
                ai, aj = articles[i], articles[j]
                if not self._within_window(ai, aj):
                    continue
                shared = signals[i] & signals[j]
                if len(shared) >= self.min_shared_signals:
                    union(i, j)
                    edge_signals[(i, j)].extend(sorted(shared))

        if self.use_semantic and n <= 400:
            idx = TFIDF({str(k): f"{a.title} {a.summary}"
                         for k, a in enumerate(articles)})
            for a, b, score in idx.pairs_above(self.tfidf_threshold):
                ia, ib = int(a), int(b)
                if self._within_window(articles[ia], articles[ib]):
                    union(ia, ib)
                    edge_signals[(min(ia, ib), max(ia, ib))].append(
                        f"semantic~{score}")

        groups: Dict[int, List[int]] = defaultdict(list)
        for i in range(n):
            groups[find(i)].append(i)

        clusters: List[Cluster] = []
        for root, members in groups.items():
            if len(members) < 2:
                continue
            arts = [articles[m] for m in members]
            sigs: Set[str] = set()
            for (i, j), sg in edge_signals.items():
                if i in members and j in members:
                    sigs.update(sg)
            entity_keys = sorted({m.entity_key for a in arts
                                  for m in a.entity_mentions})
            clusters.append(Cluster(
                kind=ClusterKind.EVENT,
                label=self._label(arts),
                article_ids=[a.article_id for a in arts],
                signals=sorted(sigs) or ["co-occurrence"],
                entity_keys=entity_keys,
                source_domains=[a.source_domain for a in arts],
                first_seen=min((a.publication_date for a in arts
                                if a.publication_date), default=0.0),
                last_seen=max((a.publication_date for a in arts), default=0.0)))
        clusters.sort(key=lambda c: (c.independent_sources, c.size), reverse=True)
        return clusters

    def _within_window(self, a: Article, b: Article) -> bool:
        if not a.publication_date or not b.publication_date:
            return True
        return abs(a.publication_date - b.publication_date) <= self.window

    @staticmethod
    def _label(arts: List[Article]) -> str:
        # prefer a shared strong entity as the label, else the earliest headline
        counts: Dict[str, int] = defaultdict(int)
        for a in arts:
            for x in a.actor_mentions + a.malware_mentions + a.cve_mentions:
                counts[x] += 1
        if counts:
            top = max(counts.items(), key=lambda kv: kv[1])[0]
            return top
        first = min(arts, key=lambda a: a.publication_date or float("inf"))
        return first.title[:80]

    def promote_events(self, clusters: List[Cluster], *,
                       known_event_ids: Optional[Set[str]] = None
                       ) -> List[NewsEvent]:
        known = known_event_ids or set()
        events: List[NewsEvent] = []
        for c in clusters:
            if c.kind != ClusterKind.EVENT:
                continue
            ev = NewsEvent(
                title=c.label, cluster_id=c.cluster_id,
                article_ids=list(c.article_ids), window_start=c.first_seen,
                window_end=c.last_seen, entity_keys=list(c.entity_keys),
                source_domains=list(c.source_domains), signals=list(c.signals))
            ev.is_new = ev.event_id not in known
            events.append(ev)
        return events


__all__ = ["EventClusterer"]
