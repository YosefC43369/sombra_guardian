"""
news_intelligence.clustering.similarity — dependency-free text similarity primitives.

Pure-stdlib SimHash (64-bit), MinHash (k-permutation), Jaccard and cosine TF-IDF
similarity used by the duplicate/event/topic clustering layers. Deterministic and
fast enough for hundreds of articles; no numpy/sklearn required.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Sequence, Set, Tuple

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9\-_.]{1,}")
_STOP = {
    "the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "for", "with",
    "as", "by", "at", "from", "is", "are", "was", "were", "be", "been", "this",
    "that", "these", "those", "it", "its", "has", "have", "had", "will", "would",
    "can", "could", "new", "said", "says", "also", "about", "into", "than", "then",
    "which", "who", "what", "when", "where", "how", "their", "they", "them", "we",
}


def tokenize(text: str) -> List[str]:
    return [w for w in _WORD_RE.findall((text or "").lower())
            if w not in _STOP and len(w) > 2]


def shingles(tokens: Sequence[str], k: int = 2) -> Set[str]:
    if k <= 1 or len(tokens) < k:
        return set(tokens)
    return {" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def _hash64(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode("utf-8"),
                                          digest_size=8).digest(), "big")


def simhash(text: str, *, bits: int = 64) -> int:
    tokens = tokenize(text)
    if not tokens:
        return 0
    counts = Counter(tokens)
    vector = [0] * bits
    for token, weight in counts.items():
        h = _hash64(token)
        for i in range(bits):
            vector[i] += weight if (h >> i) & 1 else -weight
    out = 0
    for i in range(bits):
        if vector[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def simhash_similar(a: int, b: int, *, threshold: int = 3) -> bool:
    if a == 0 or b == 0:
        return False
    return hamming(a, b) <= threshold


def minhash(text: str, *, num_perm: int = 64, k: int = 2) -> List[int]:
    tokens = tokenize(text)
    sh = shingles(tokens, k=k) or set(tokens)
    if not sh:
        return [0] * num_perm
    hashes = [int.from_bytes(hashlib.blake2b(
        s.encode("utf-8"), digest_size=8).digest(), "big") for s in sh]
    sig: List[int] = []
    mask = (1 << 64) - 1
    for i in range(num_perm):
        a = (i * 2654435761 + 1) & mask
        b = (i * 40503 + 12345) & mask
        sig.append(min(((a * h + b) & mask) for h in hashes))
    return sig


def minhash_jaccard(sig_a: List[int], sig_b: List[int]) -> float:
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0
    same = sum(1 for x, y in zip(sig_a, sig_b) if x == y)
    return same / len(sig_a)


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


class TFIDF:
    """A tiny TF-IDF cosine-similarity index over a fixed document set."""

    def __init__(self, docs: Dict[str, str], *, k: int = 1):
        self.ids = list(docs.keys())
        self.tokens: Dict[str, List[str]] = {
            d: list(shingles(tokenize(t), k=k)) if k > 1 else tokenize(t)
            for d, t in docs.items()}
        self.df: Counter = Counter()
        for toks in self.tokens.values():
            for t in set(toks):
                self.df[t] += 1
        self.n = max(1, len(self.ids))
        self.vectors: Dict[str, Dict[str, float]] = {
            d: self._vec(toks) for d, toks in self.tokens.items()}

    def _vec(self, tokens: List[str]) -> Dict[str, float]:
        tf = Counter(tokens)
        vec: Dict[str, float] = {}
        for term, freq in tf.items():
            idf = math.log((self.n + 1) / (1 + self.df.get(term, 0))) + 1.0
            vec[term] = freq * idf
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {t: v / norm for t, v in vec.items()}

    def similarity(self, id_a: str, id_b: str) -> float:
        va, vb = self.vectors.get(id_a, {}), self.vectors.get(id_b, {})
        if not va or not vb:
            return 0.0
        small, big = (va, vb) if len(va) < len(vb) else (vb, va)
        return sum(w * big.get(t, 0.0) for t, w in small.items())

    def pairs_above(self, threshold: float) -> List[Tuple[str, str, float]]:
        out: List[Tuple[str, str, float]] = []
        for i in range(len(self.ids)):
            for j in range(i + 1, len(self.ids)):
                s = self.similarity(self.ids[i], self.ids[j])
                if s >= threshold:
                    out.append((self.ids[i], self.ids[j], round(s, 4)))
        return out


__all__ = ["tokenize", "shingles", "simhash", "hamming", "simhash_similar",
           "minhash", "minhash_jaccard", "jaccard", "TFIDF"]
