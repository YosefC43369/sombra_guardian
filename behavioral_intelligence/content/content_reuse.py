"""
behavioral_intelligence.content.content_reuse — near-duplicate content detection
across posts and platforms (spec §18–19).

Four methods, all stdlib:

  * SHA-256 — exact duplicate of normalised text (via the observation's
    ``content_hash``).
  * SimHash — 64-bit locality-sensitive fingerprint; Hamming distance estimates
    similarity, cheap to compare pairwise.
  * MinHash — k-permutation min-hash over token shingles; estimates Jaccard
    similarity, robust to reordering.
  * Cosine — TF-vector cosine similarity, the classic bag-of-words measure.

``detect_reuse`` compares posts pairwise (blocked by SimHash bucket to stay
sub-quadratic on large inputs) and returns ``ContentReuse`` records with the
method, score, the two sources and their temporal distance.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from typing import Dict, List, Sequence, Set, Tuple

from ..models.observation import Observation
from ..models.topic import ContentReuse
from ..linguistic.keyword_engine import tokenize

_MASK64 = (1 << 64) - 1


def _hash64(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(),
                          "big")


def simhash(tokens: Sequence[str]) -> int:
    """64-bit SimHash of a token multiset."""
    if not tokens:
        return 0
    vector = [0] * 64
    weights: Dict[str, int] = defaultdict(int)
    for t in tokens:
        weights[t] += 1
    for token, w in weights.items():
        h = _hash64(token)
        for i in range(64):
            vector[i] += w if (h >> i) & 1 else -w
    out = 0
    for i in range(64):
        if vector[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin((a ^ b) & _MASK64).count("1")


def simhash_similarity(a: int, b: int) -> float:
    return 1.0 - hamming(a, b) / 64.0


def _shingles(tokens: Sequence[str], k: int = 3) -> Set[str]:
    if len(tokens) < k:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def minhash(tokens: Sequence[str], *, num_perm: int = 64, k: int = 3) -> List[int]:
    """k-permutation MinHash signature over token shingles."""
    shingles = _shingles(tokens, k)
    if not shingles:
        return [0] * num_perm
    base = [int.from_bytes(hashlib.blake2b(s.encode("utf-8"),
            digest_size=8).digest(), "big") for s in shingles]
    sig: List[int] = []
    for p in range(num_perm):
        # cheap universal hashing: mix each base hash with the permutation index
        a = (2 * p + 1)
        b = (p * 0x9E3779B97F4A7C15) & _MASK64
        sig.append(min(((a * h + b) & _MASK64) for h in base))
    return sig


def minhash_similarity(sig_a: Sequence[int], sig_b: Sequence[int]) -> float:
    n = min(len(sig_a), len(sig_b))
    if n == 0:
        return 0.0
    return sum(1 for i in range(n) if sig_a[i] == sig_b[i]) / n


def cosine_similarity(tokens_a: Sequence[str], tokens_b: Sequence[str]) -> float:
    va: Dict[str, int] = defaultdict(int)
    vb: Dict[str, int] = defaultdict(int)
    for t in tokens_a:
        va[t] += 1
    for t in tokens_b:
        vb[t] += 1
    if not va or not vb:
        return 0.0
    common = set(va) & set(vb)
    dot = sum(va[t] * vb[t] for t in common)
    na = math.sqrt(sum(v * v for v in va.values()))
    nb = math.sqrt(sum(v * v for v in vb.values()))
    return dot / (na * nb) if na and nb else 0.0


def detect_reuse(observations: Sequence[Observation], *,
                 method: str = "simhash", threshold: float = 0.8,
                 max_pairs: int = 2000) -> List[ContentReuse]:
    """Detect near-duplicate content pairs. ``method`` is one of
    exact|simhash|minhash|cosine. SimHash bucketing (top 16 bits) blocks the
    pairwise comparison so this stays tractable on large corpora."""
    posts = [o for o in observations if (o.text or "").strip()]
    if len(posts) < 2:
        return []

    results: List[ContentReuse] = []

    if method == "exact":
        by_hash: Dict[str, List[Observation]] = defaultdict(list)
        for o in posts:
            by_hash[o.content_hash].append(o)
        for group in by_hash.values():
            for gi in range(len(group)):
                for gj in range(gi + 1, len(group)):
                    a, b = group[gi], group[gj]
                    results.append(ContentReuse(
                        hash_a=a.content_hash, hash_b=b.content_hash,
                        source_a=a.source_url or a.observation_id,
                        source_b=b.source_url or b.observation_id,
                        similarity=1.0, method="sha256",
                        timestamp_a=a.timestamp, timestamp_b=b.timestamp,
                        temporal_distance=abs(a.timestamp - b.timestamp)))
        return results[:max_pairs]

    # precompute per-post token/fingerprint
    toks = [tokenize(o.text) for o in posts]
    sh = [simhash(t) for t in toks]

    # block by top-16 bits of the simhash to avoid full O(n^2)
    buckets: Dict[int, List[int]] = defaultdict(list)
    for idx, h in enumerate(sh):
        buckets[h >> 48].append(idx)
    # also compare across adjacent buckets for near-boundary items via a global
    # cap: if the corpus is small, just compare all pairs.
    pairs: List[Tuple[int, int]] = []
    if len(posts) <= 300:
        for i in range(len(posts)):
            for j in range(i + 1, len(posts)):
                pairs.append((i, j))
    else:
        for members in buckets.values():
            for mi in range(len(members)):
                for mj in range(mi + 1, len(members)):
                    pairs.append((members[mi], members[mj]))

    mh: List[List[int]] = []
    if method == "minhash":
        mh = [minhash(t) for t in toks]

    for i, j in pairs[:max_pairs * 4]:
        if method == "simhash":
            sim = simhash_similarity(sh[i], sh[j])
        elif method == "minhash":
            sim = minhash_similarity(mh[i], mh[j])
        elif method == "cosine":
            sim = cosine_similarity(toks[i], toks[j])
        else:
            sim = simhash_similarity(sh[i], sh[j])
        if sim >= threshold:
            a, b = posts[i], posts[j]
            results.append(ContentReuse(
                hash_a=a.content_hash, hash_b=b.content_hash,
                source_a=a.source_url or a.observation_id,
                source_b=b.source_url or b.observation_id,
                similarity=sim, method=method,
                timestamp_a=a.timestamp, timestamp_b=b.timestamp,
                temporal_distance=abs(a.timestamp - b.timestamp)))
            if len(results) >= max_pairs:
                break
    results.sort(key=lambda r: r.similarity, reverse=True)
    return results
