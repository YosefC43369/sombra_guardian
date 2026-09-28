"""
news_intelligence.search — internal search + advanced filtering over the corpus.

``SearchEngine`` answers free-text and structured queries (by entity, actor, campaign,
malware, CVE, organization, country, date range, language, source, topic) against the
stored articles, ranking by term overlap and recency. ``FilterEngine`` provides the
canned filters the Telegram surface exposes (last 24h / 7d / month, vendor-only,
government-only, by entity type, by language). Both are read-only and deterministic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models.article import Article
from .models.entity import EntityType, normalize_value
from .clustering.similarity import tokenize


@dataclass
class SearchQuery:
    text: str = ""
    entity: str = ""
    entity_type: str = ""
    actor: str = ""
    campaign: str = ""
    malware: str = ""
    cve: str = ""
    organization: str = ""
    country: str = ""
    source: str = ""
    language: str = ""
    topic: str = ""
    since: float = 0.0
    until: float = 0.0
    limit: int = 50


@dataclass
class SearchHit:
    article_id: str
    title: str
    url: str
    source: str
    published: float
    score: float
    matched: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"article_id": self.article_id, "title": self.title, "url": self.url,
                "source": self.source, "published": self.published,
                "score": round(self.score, 4), "matched": self.matched}


class SearchEngine:
    def __init__(self, store):
        self.store = store

    def _candidate_ids(self, q: SearchQuery) -> Optional[set]:
        """Narrow to article ids that match the structured entity constraints
        (intersection). Returns None to mean 'no entity constraint'."""
        constraints = []
        entity_pairs = [
            (q.actor, EntityType.THREAT_ACTOR.value),
            (q.malware, EntityType.MALWARE_FAMILY.value),
            (q.cve, EntityType.CVE.value),
            (q.organization, EntityType.ORGANIZATION.value),
            (q.country, EntityType.COUNTRY.value),
            (q.campaign, EntityType.CAMPAIGN.value),
        ]
        if q.entity:
            entity_pairs.append((q.entity, q.entity_type))
        for value, etype in entity_pairs:
            if not value:
                continue
            et = EntityType.coerce(etype) if etype else None
            norm = normalize_value(et, value) if et else value
            ids = set(self.store.articles_for_entity(
                value=norm, entity_type=(et.value if et else ""), since=q.since))
            constraints.append(ids)
        if not constraints:
            return None
        result = constraints[0]
        for s in constraints[1:]:
            result &= s
        return result

    def search(self, q: SearchQuery) -> List[SearchHit]:
        ids = self._candidate_ids(q)
        if ids is not None:
            articles = [a for a in (self.store.get_article(i) for i in ids) if a]
        else:
            articles = self.store.list_articles(since=q.since, until=q.until,
                                                source_domain="", limit=2000)
        terms = tokenize(q.text) if q.text else []
        hits: List[SearchHit] = []
        for a in articles:
            if a.duplicate_of:
                continue
            if q.language and a.language and not a.language.startswith(q.language):
                continue
            if q.source and q.source.lower() not in (
                    a.source_name.lower() + " " + a.source_domain.lower()):
                continue
            if q.since and (a.publication_date or 0) < q.since:
                continue
            if q.until and (a.publication_date or 0) > q.until:
                continue
            score, matched = self._score(a, terms, q)
            if terms and score <= 0 and ids is None:
                continue
            hits.append(SearchHit(
                article_id=a.article_id, title=a.title,
                url=a.canonical_url or a.url,
                source=a.source_name or a.source_domain,
                published=a.publication_date, score=score, matched=matched))
        hits.sort(key=lambda h: (h.score, h.published), reverse=True)
        return hits[: q.limit or 50]

    def _score(self, a: Article, terms: List[str], q: SearchQuery):
        matched: List[str] = []
        score = 0.0
        if terms:
            haystack = set(tokenize(f"{a.title} {a.summary}"))
            for t in terms:
                if t in haystack:
                    score += 2.0 if t in tokenize(a.title) else 1.0
                    matched.append(t)
        if q.topic:
            tl = q.topic.lower()
            if tl in (a.title + " " + a.summary).lower() or tl in a.tags:
                score += 1.5
                matched.append(f"topic:{q.topic}")
        # recency nudge
        age_days = a.age_days
        score += max(0.0, 1.0 - age_days / 30.0)
        if not terms and not q.topic:
            score += 1.0  # structured-only query: keep all candidates
        return score, matched

    def simple(self, text: str, *, limit: int = 25, since: float = 0.0
               ) -> List[SearchHit]:
        return self.search(SearchQuery(text=text, limit=limit, since=since))


class FilterEngine:
    def __init__(self, store):
        self.store = store

    def _window(self, days: float, now: Optional[float]) -> float:
        now = now or time.time()
        return now - days * 86400

    def last_hours(self, hours: int = 24, *, now=None, limit=100) -> List[Article]:
        return self.store.list_articles(since=self._window(hours / 24.0, now),
                                        limit=limit)

    def last_days(self, days: int = 7, *, now=None, limit=500) -> List[Article]:
        return self.store.list_articles(since=self._window(days, now), limit=limit)

    def by_source_class(self, source_class: str, *, since=0.0, limit=500
                        ) -> List[Article]:
        return [a for a in self.store.list_articles(since=since, limit=limit)
                if a.source_class.value == source_class]

    def vendor_only(self, **kw) -> List[Article]:
        return self.by_source_class("vendor", **kw)

    def government_only(self, **kw) -> List[Article]:
        return [a for a in self.store.list_articles(
            since=kw.get("since", 0.0), limit=kw.get("limit", 500))
            if a.source_class.value in ("government", "standards")]

    def with_entity_type(self, entity_type: str, *, since=0.0, limit=500
                         ) -> List[Article]:
        et = EntityType.coerce(entity_type)
        out = []
        for a in self.store.list_articles(since=since, limit=limit):
            if any(m.entity_type == et for m in a.entity_mentions):
                out.append(a)
        return out

    def by_language(self, language: str, *, since=0.0, limit=500) -> List[Article]:
        return [a for a in self.store.list_articles(since=since, limit=limit)
                if (a.language or "").startswith(language)]


__all__ = ["SearchQuery", "SearchHit", "SearchEngine", "FilterEngine"]
