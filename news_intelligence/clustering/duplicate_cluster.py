"""
news_intelligence.clustering.duplicate_cluster — duplicate / near-duplicate detection.

Layered detection, cheapest signal first (spec DUPLICATE DETECTION ENGINE):
  1. canonical URL — a syndicated copy declaring the original's canonical link;
  2. content hash (SHA256) — byte-identical title+summary+domain;
  3. SimHash Hamming distance — near-duplicate wording;
  4. MinHash Jaccard — shingle-set overlap (catches reordered/edited copies);
  5. TF-IDF cosine — semantic near-duplicate fallback.

Returns duplicate ``Cluster`` objects whose members share an original, with the
matching signal recorded on each cluster so the grouping is auditable. The pipeline
uses ``pick_original`` to choose the canonical article (earliest published, most
reliable source) and marks the rest ``duplicate_of`` it.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..models.article import Article
from ..models.topic import Cluster, ClusterKind
from .similarity import (simhash, simhash_similar, minhash, minhash_jaccard,
                         TFIDF)


class DuplicateDetector:
    def __init__(self, *, simhash_hamming: int = 3, minhash_jaccard: float = 0.7,
                 tfidf_threshold: float = 0.7, use_tfidf: bool = True):
        self.simhash_hamming = simhash_hamming
        self.minhash_jaccard = minhash_jaccard
        self.tfidf_threshold = tfidf_threshold
        self.use_tfidf = use_tfidf

    def _blob(self, a: Article) -> str:
        return f"{a.title} {a.summary}"

    def find_duplicates(self, articles: List[Article]) -> List[Cluster]:
        """Group articles into near-duplicate clusters (singletons omitted)."""
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

        # precompute fingerprints
        sims = [a.simhash or simhash(self._blob(a)) for a in articles]
        mins = [minhash(self._blob(a)) for a in articles]
        signal: Dict[Tuple[int, int], str] = {}

        for i in range(n):
            for j in range(i + 1, n):
                sig = self._match(articles[i], articles[j], sims[i], sims[j],
                                  mins[i], mins[j])
                if sig:
                    union(i, j)
                    signal[(i, j)] = sig

        # optional TF-IDF pass over still-unmatched pairs
        if self.use_tfidf and n <= 400:
            idx = TFIDF({str(k): self._blob(a) for k, a in enumerate(articles)})
            for a, b, score in idx.pairs_above(self.tfidf_threshold):
                ia, ib = int(a), int(b)
                if find(ia) != find(ib):
                    union(ia, ib)
                    signal[(min(ia, ib), max(ia, ib))] = f"tfidf~{score}"

        groups: Dict[int, List[int]] = {}
        for i in range(n):
            groups.setdefault(find(i), []).append(i)

        clusters: List[Cluster] = []
        for root, members in groups.items():
            if len(members) < 2:
                continue
            arts = [articles[m] for m in members]
            sigs = sorted({s for (i, j), s in signal.items()
                           if i in members and j in members})
            first = min((a.publication_date for a in arts if a.publication_date),
                        default=0.0)
            last = max((a.publication_date for a in arts), default=0.0)
            clusters.append(Cluster(
                kind=ClusterKind.DUPLICATE,
                label=arts[0].title[:80],
                article_ids=[a.article_id for a in arts],
                signals=sigs or ["near-duplicate"],
                source_domains=[a.source_domain for a in arts],
                first_seen=first, last_seen=last,
                detail={"original": self.pick_original(arts).article_id}))
        return clusters

    def _match(self, a: Article, b: Article, sa: int, sb: int,
               ma: List[int], mb: List[int]) -> Optional[str]:
        if a.canonical_url and b.canonical_url and \
                a.canonical_url.lower() == b.canonical_url.lower():
            return "canonical_url"
        if a.content_hash and a.content_hash == b.content_hash:
            return "content_hash"
        if simhash_similar(sa, sb, threshold=self.simhash_hamming):
            return f"simhash<={self.simhash_hamming}"
        jac = minhash_jaccard(ma, mb)
        if jac >= self.minhash_jaccard:
            return f"minhash~{round(jac, 3)}"
        return None

    @staticmethod
    def pick_original(articles: List[Article]) -> Article:
        """Earliest published wins; ties broken by source reliability (class)."""
        order = {"government": 0, "standards": 0, "vendor": 1, "research": 2,
                 "community": 3, "aggregator": 4, "feed": 5, "unknown": 6}

        def key(a: Article):
            pub = a.publication_date or float("inf")
            return (pub, order.get(a.source_class.value, 9))
        return min(articles, key=key)

    def mark_duplicates(self, articles: List[Article]) -> List[Cluster]:
        """Find duplicate clusters AND stamp ``duplicate_of`` on the copies."""
        clusters = self.find_duplicates(articles)
        by_id = {a.article_id: a for a in articles}
        for c in clusters:
            original_id = c.detail.get("original", "")
            for aid in c.article_ids:
                art = by_id.get(aid)
                if art is not None and aid != original_id:
                    art.duplicate_of = original_id
        return clusters


__all__ = ["DuplicateDetector"]
