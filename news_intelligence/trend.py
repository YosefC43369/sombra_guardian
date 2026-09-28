"""
news_intelligence.trend — trend detection over the news corpus.

Detects shifts in coverage volume for entities (CVEs, malware families, actors,
topics) by comparing a recent window against the preceding window of equal length.
Every trend output carries its *sample size* and *observation window* (spec: "Trend
output must include sample size and observation window") so a spike from 1→2 articles
is never dressed up as a surge.

Signals produced:
  * rising / falling coverage for an entity;
  * cross-vendor spread (a malware/CVE discussed by many distinct outlets);
  * emerging entity (absent in the prior window, present now);
  * topic momentum (ransomware/exploitation coverage rising).

Deterministic and evidence-anchored: each trend lists the article ids behind it.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .models.article import Article


@dataclass
class Trend:
    subject: str
    subject_type: str
    direction: str                       # rising | falling | emerging | steady
    current_count: int
    prior_count: int
    change_ratio: float                  # current / max(1, prior)
    distinct_sources: int
    window_days: int
    sample_size: int                     # total articles considered
    article_ids: List[str] = field(default_factory=list)
    detail: Dict[str, object] = field(default_factory=dict)

    @property
    def is_significant(self) -> bool:
        return self.current_count >= 3 and self.distinct_sources >= 2

    def to_dict(self) -> Dict[str, object]:
        d = asdict(self)
        d["is_significant"] = self.is_significant
        return d


class TrendEngine:
    def __init__(self, *, window_days: int = 7, min_sample: int = 3):
        self.window_days = window_days
        self.min_sample = min_sample

    def _bucketize(self, articles: List[Article], accessor, now: float):
        """Return (current, prior) dicts value -> {count, sources, ids}."""
        w = self.window_days * 86400
        cur_start, prior_start = now - w, now - 2 * w
        current: Dict[str, Dict] = defaultdict(
            lambda: {"count": 0, "sources": set(), "ids": []})
        prior: Dict[str, Dict] = defaultdict(
            lambda: {"count": 0, "sources": set(), "ids": []})
        for a in articles:
            if a.duplicate_of:
                continue
            ts = a.publication_date or a.ingestion_date
            for val in set(accessor(a)):
                if ts >= cur_start:
                    b = current[val]
                elif ts >= prior_start:
                    b = prior[val]
                else:
                    continue
                b["count"] += 1
                b["sources"].add(a.source_domain)
                b["ids"].append(a.article_id)
        return current, prior

    def detect(self, articles: List[Article], *, accessor, subject_type: str,
               now: Optional[float] = None) -> List[Trend]:
        now = now or time.time()
        sample = len([a for a in articles if not a.duplicate_of])
        current, prior = self._bucketize(articles, accessor, now)
        trends: List[Trend] = []
        for val, cur in current.items():
            pri = prior.get(val, {"count": 0, "sources": set(), "ids": []})
            cc, pc = cur["count"], pri["count"]
            ratio = cc / max(1, pc)
            if pc == 0 and cc >= self.min_sample:
                direction = "emerging"
            elif ratio >= 1.5 and cc >= self.min_sample:
                direction = "rising"
            elif ratio <= 0.5 and pc >= self.min_sample:
                direction = "falling"
            else:
                direction = "steady"
            if direction == "steady" and cc < self.min_sample:
                continue
            trends.append(Trend(
                subject=val, subject_type=subject_type, direction=direction,
                current_count=cc, prior_count=pc, change_ratio=round(ratio, 2),
                distinct_sources=len(cur["sources"]),
                window_days=self.window_days, sample_size=sample,
                article_ids=cur["ids"][:50]))
        trends.sort(key=lambda t: (t.direction != "emerging", -t.current_count,
                                   -t.change_ratio))
        return trends

    # convenience accessors --------------------------------------------- #
    def cve_trends(self, articles, *, now=None):
        return self.detect(articles, accessor=lambda a: a.cve_mentions,
                           subject_type="cve", now=now)

    def malware_trends(self, articles, *, now=None):
        return self.detect(articles, accessor=lambda a: a.malware_mentions,
                           subject_type="malware", now=now)

    def actor_trends(self, articles, *, now=None):
        return self.detect(articles, accessor=lambda a: a.actor_mentions,
                           subject_type="actor", now=now)

    def country_trends(self, articles, *, now=None):
        return self.detect(articles, accessor=lambda a: a.country_mentions,
                           subject_type="country", now=now)

    def topic_trends(self, articles, *, now=None):
        """Momentum for coarse topics via tag/keyword presence."""
        def topics(a: Article):
            text = (a.title + " " + a.summary).lower()
            hits = []
            for topic in ("ransomware", "phishing", "zero-day", "supply chain",
                          "data breach", "espionage", "ddos", "botnet",
                          "vulnerability", "exploitation"):
                if topic.replace("-", " ") in text or topic in a.tags:
                    hits.append(topic)
            return hits
        return self.detect(articles, accessor=topics, subject_type="topic", now=now)

    def all_trends(self, articles, *, now=None) -> Dict[str, List[Trend]]:
        return {
            "cve": self.cve_trends(articles, now=now),
            "malware": self.malware_trends(articles, now=now),
            "actor": self.actor_trends(articles, now=now),
            "country": self.country_trends(articles, now=now),
            "topic": self.topic_trends(articles, now=now),
        }


__all__ = ["Trend", "TrendEngine"]
