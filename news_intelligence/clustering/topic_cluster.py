"""
news_intelligence.clustering.topic_cluster — thematic topic clustering.

Groups articles into topics by their dominant shared entities and TF-IDF keyword
terms. Unlike event clustering (which is time-bounded and about one incident), a
topic spans time ("ransomware", "Ivanti vulnerabilities", "Volt Typhoon activity").
Each ``Topic`` records the terms/entity keys that define it and the articles scored
into it, so a topic is inspectable, not a black-box embedding.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional

from ..models.article import Article
from ..models.topic import Topic
from .similarity import tokenize


class TopicClusterer:
    def __init__(self, *, min_articles: int = 2, top_terms: int = 6):
        self.min_articles = min_articles
        self.top_terms = top_terms

    def cluster_by_entity(self, articles: List[Article]) -> List[Topic]:
        """One topic per salient entity that recurs across >= min_articles."""
        articles = [a for a in articles if not a.duplicate_of]
        buckets: Dict[str, List[Article]] = defaultdict(list)
        labels: Dict[str, str] = {}
        for a in articles:
            salient = (a.actor_mentions + a.malware_mentions + a.cve_mentions
                       + a.organization_mentions)
            for value in set(salient):
                key = value.lower()
                buckets[key].append(a)
                labels[key] = value
        topics: List[Topic] = []
        for key, arts in buckets.items():
            if len(arts) < self.min_articles:
                continue
            terms = self._top_terms(arts)
            entity_keys = sorted({m.entity_key for a in arts
                                  for m in a.entity_mentions
                                  if m.value.lower() == key})
            topics.append(Topic(
                label=labels[key], terms=terms, entity_keys=entity_keys,
                article_ids=[a.article_id for a in arts],
                first_seen=min((a.publication_date for a in arts
                                if a.publication_date), default=0.0),
                last_seen=max((a.publication_date for a in arts), default=0.0),
                detail={"size": len(arts)}))
        topics.sort(key=lambda t: t.size, reverse=True)
        return topics

    def _top_terms(self, arts: List[Article]) -> List[str]:
        counter: Counter = Counter()
        for a in arts:
            counter.update(tokenize(f"{a.title} {a.summary}"))
        return [t for t, _ in counter.most_common(self.top_terms)]

    def keyword_topics(self, articles: List[Article], *, top_n: int = 20
                       ) -> List[Topic]:
        """Corpus-wide keyword topics ranked by document frequency."""
        articles = [a for a in articles if not a.duplicate_of]
        df: Counter = Counter()
        holders: Dict[str, List[Article]] = defaultdict(list)
        for a in articles:
            for term in set(tokenize(f"{a.title} {a.summary}")):
                df[term] += 1
                holders[term].append(a)
        topics: List[Topic] = []
        for term, count in df.most_common(top_n):
            if count < self.min_articles:
                continue
            arts = holders[term]
            topics.append(Topic(
                label=term, terms=[term],
                article_ids=[a.article_id for a in arts],
                first_seen=min((a.publication_date for a in arts
                                if a.publication_date), default=0.0),
                last_seen=max((a.publication_date for a in arts), default=0.0),
                detail={"document_frequency": count}))
        return topics


__all__ = ["TopicClusterer"]
