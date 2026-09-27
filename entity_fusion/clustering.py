"""
entity_fusion.clustering — group entities that refer to the same real-world
thing into clusters, using pairwise similarity plus union-find.

APPROACH
--------
Naive all-pairs comparison is O(n²), which is fine for a single dossier but
wasteful at scale. This module first *blocks* entities into candidate buckets
using cheap exact keys (canonical value, homoglyph skeleton, email domain,
username core, hard-identifier hashes). Only entities that share a block are
compared with the (more expensive) ``SimilarityEngine``. Pairs scoring at or
above ``threshold`` are unioned; the connected components are the clusters.

Each merge decision keeps the ``SimilarityResult`` that justified it, so a
cluster can explain *why* its members were joined — the same fact-not-inference
discipline used everywhere else in the engine.

Pure stdlib. The union-find is the standard weighted/path-compressed structure.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .entity import Entity, EntityType
from .similarity import SimilarityEngine, SimilarityResult
from . import normalization as norm


# --------------------------------------------------------------------------- #
# Union-Find                                                                   #
# --------------------------------------------------------------------------- #

class UnionFind:
    """Disjoint-set forest with path compression and union by rank."""

    def __init__(self, items: Sequence[str] = ()):
        items = list(items)   # may be a generator; must not be consumed twice
        self.parent: Dict[str, str] = {i: i for i in items}
        self.rank: Dict[str, int] = {i: 0 for i in items}

    def add(self, item: str) -> None:
        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        # path compression
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1

    def groups(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = defaultdict(list)
        for item in self.parent:
            out[self.find(item)].append(item)
        return dict(out)


# --------------------------------------------------------------------------- #
# Clustering                                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class Cluster:
    """A connected group of entities judged to be the same thing, plus the
    pairwise similarity results that linked them."""
    id: str
    members: List[Entity] = field(default_factory=list)
    links: List[SimilarityResult] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def types(self) -> List[str]:
        return sorted({m.type.value for m in self.members})

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "size": self.size,
            "types": self.types,
            "members": [m.id for m in self.members],
            "links": [l.to_dict() for l in self.links],
        }


@dataclass
class ClusterReport:
    clusters: List[Cluster]
    comparisons: int = 0
    threshold: float = 0.0

    @property
    def singletons(self) -> int:
        return sum(1 for c in self.clusters if c.size == 1)

    def stats(self) -> dict:
        return {
            "clusters": len(self.clusters),
            "multi_member": sum(1 for c in self.clusters if c.size > 1),
            "singletons": self.singletons,
            "comparisons": self.comparisons,
            "threshold": self.threshold,
        }


class Clusterer:
    """Blocking + pairwise-similarity + union-find clusterer.

    ``threshold`` is the minimum similarity score (0..1) for two entities to be
    considered the same. ``block_across_types`` controls whether cross-type
    correlation is attempted (e.g. a username entity and a person entity sharing
    a handle) — on by default because that is exactly the point of *fusion*.
    """

    def __init__(self, engine: Optional[SimilarityEngine] = None, *,
                 threshold: float = 0.82,
                 block_across_types: bool = True,
                 max_block_size: int = 400):
        self.engine = engine or SimilarityEngine()
        self.threshold = threshold
        self.block_across_types = block_across_types
        self.max_block_size = max_block_size

    # -- blocking ---------------------------------------------------------- #

    def _block_keys(self, e: Entity) -> List[str]:
        """Cheap keys under which this entity might collide with a duplicate.
        Two entities are compared only if they share at least one key."""
        keys: List[str] = []
        if e.normalized:
            keys.append(f"norm:{e.type.value}:{e.normalized}"
                        if not self.block_across_types else f"norm:{e.normalized}")
        skel = norm.skeleton(e.value)
        if skel:
            keys.append(f"skel:{skel}")
        # handle-core key ties usernames/persons/emails together
        core = norm.username_core(e.value)
        if core:
            keys.append(f"core:{core}")
        for meta_key in ("email", "display_name", "name"):
            v = e.metadata.get(meta_key)
            if v:
                if meta_key == "email":
                    ce = norm.canonical_email(str(v))
                    if ce:
                        keys.append(f"email:{ce}")
                else:
                    keys.append(f"name:{norm.skeleton(str(v))}")
        for hard in ("avatar_sha256", "avatar_phash", "wallet",
                     "certificate_fingerprint"):
            v = e.metadata.get(hard)
            if v:
                keys.append(f"{hard}:{str(v).lower()}")
        return keys

    def _candidate_pairs(self, entities: List[Entity]) -> List[Tuple[int, int]]:
        buckets: Dict[str, List[int]] = defaultdict(list)
        for idx, e in enumerate(entities):
            for key in self._block_keys(e):
                buckets[key].append(idx)
        seen: set = set()
        pairs: List[Tuple[int, int]] = []
        for members in buckets.values():
            if len(members) < 2 or len(members) > self.max_block_size:
                # Oversized blocks (e.g. a shared, generic name) are skipped to
                # avoid a quadratic blow-up on a low-information key.
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    a, b = members[i], members[j]
                    key = (a, b) if a < b else (b, a)
                    if key not in seen:
                        seen.add(key)
                        pairs.append(key)
        return pairs

    # -- clustering -------------------------------------------------------- #

    def cluster(self, entities: Sequence[Entity]) -> ClusterReport:
        """Cluster ``entities`` and return a report. Idempotent and pure."""
        entities = list(entities)
        uf = UnionFind(e.id for e in entities)
        pairs = self._candidate_pairs(entities)
        links: List[SimilarityResult] = []
        comparisons = 0
        for i, j in pairs:
            comparisons += 1
            res = self.engine.score_entities(entities[i], entities[j])
            if res.score >= self.threshold:
                uf.union(entities[i].id, entities[j].id)
                links.append(res)

        by_id = {e.id: e for e in entities}
        links_by_root: Dict[str, List[SimilarityResult]] = defaultdict(list)
        for res in links:
            links_by_root[uf.find(res.a_id)].append(res)

        clusters: List[Cluster] = []
        for root, member_ids in uf.groups().items():
            members = [by_id[mid] for mid in member_ids if mid in by_id]
            clusters.append(Cluster(id=root, members=members,
                                    links=links_by_root.get(root, [])))
        clusters.sort(key=lambda c: (-c.size, c.id))
        return ClusterReport(clusters=clusters, comparisons=comparisons,
                             threshold=self.threshold)
