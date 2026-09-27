"""
entity_fusion.similarity — how alike are two entities, and *why*.

This module answers two questions:

  1. Low level: how similar are two strings? (edit distance, Jaro-Winkler,
     token Jaccard, character n-gram cosine — all pure stdlib.)
  2. High level: given two entities, how strongly does the evidence say they are
     the same real-world thing, broken down per signal so the score is
     explainable rather than a black box.

The philosophy matches the rest of the repo: never emit an opaque certainty.
``score_entities`` returns a ``SimilarityResult`` carrying every contributing
signal, its raw value and its weight, so a human (or the confidence engine, or a
report) can see exactly which facts drove the number. A single hard identifier
match (same canonical email, same certificate fingerprint, same crypto address)
is treated as near-conclusive; soft signals (name/bio/timezone) accumulate but
never on their own assert identity.

Weights live in ``DEFAULT_WEIGHTS`` and are injectable, so an operator can tune
the model for their environment without touching the scoring logic.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .entity import Entity, EntityType
from . import normalization as norm


# --------------------------------------------------------------------------- #
# String similarity primitives                                                 #
# --------------------------------------------------------------------------- #

def levenshtein(a: str, b: str) -> int:
    """Classic edit distance, O(len(a)*len(b)) time, O(min) space (two-row)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            insert = previous[j] + 1
            delete = current[j - 1] + 1
            replace = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def levenshtein_ratio(a: str, b: str) -> float:
    """Edit distance folded to a [0, 1] similarity (1.0 == identical)."""
    if not a and not b:
        return 1.0
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1.0 - (levenshtein(a, b) / longest)


def jaro(a: str, b: str) -> float:
    """Jaro similarity in [0, 1] — good for short strings like names/handles."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    match_dist = max(len(a), len(b)) // 2 - 1
    match_dist = max(match_dist, 0)
    a_flags = [False] * len(a)
    b_flags = [False] * len(b)
    matches = 0
    for i, ca in enumerate(a):
        lo = max(0, i - match_dist)
        hi = min(i + match_dist + 1, len(b))
        for j in range(lo, hi):
            if not b_flags[j] and b[j] == ca:
                a_flags[i] = b_flags[j] = True
                matches += 1
                break
    if matches == 0:
        return 0.0
    # transpositions
    t = 0
    k = 0
    for i, ca in enumerate(a):
        if a_flags[i]:
            while not b_flags[k]:
                k += 1
            if ca != b[k]:
                t += 1
            k += 1
    t //= 2
    m = matches
    return (m / len(a) + m / len(b) + (m - t) / m) / 3.0


def jaro_winkler(a: str, b: str, *, prefix_weight: float = 0.1) -> float:
    """Jaro-Winkler: Jaro boosted for a shared prefix (up to 4 chars). The
    default metric for usernames and display names."""
    base = jaro(a, b)
    prefix = 0
    for ca, cb in zip(a[:4], b[:4]):
        if ca == cb:
            prefix += 1
        else:
            break
    return base + prefix * prefix_weight * (1 - base)


def token_jaccard(a: str, b: str) -> float:
    """Jaccard overlap of whitespace tokens — order-independent set similarity
    for multi-word fields (display names, org names, bios)."""
    sa = set(a.split())
    sb = set(b.split())
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def _ngrams(text: str, n: int) -> Counter:
    text = f"  {text}  "  # pad so edge n-grams are represented
    return Counter(text[i:i + n] for i in range(len(text) - n + 1))


def ngram_cosine(a: str, b: str, *, n: int = 3) -> float:
    """Cosine similarity over character n-gram frequency vectors — robust to
    word reordering and small typos, good for longer text like bios."""
    if not a or not b:
        return 1.0 if a == b else 0.0
    va, vb = _ngrams(a, n), _ngrams(b, n)
    common = set(va) & set(vb)
    if not common:
        return 0.0
    dot = sum(va[g] * vb[g] for g in common)
    mag_a = math.sqrt(sum(v * v for v in va.values()))
    mag_b = math.sqrt(sum(v * v for v in vb.values()))
    return dot / (mag_a * mag_b) if mag_a and mag_b else 0.0


def jaccard(a: Sequence[Any], b: Sequence[Any]) -> float:
    """Jaccard index over two arbitrary collections (e.g. hashtag sets, shared
    links). Returns 0.0 for two empty inputs (no evidence, not identity)."""
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def best_name_similarity(a: str, b: str) -> float:
    """Blend the name-oriented metrics into one [0, 1] score. Uses the max of
    Jaro-Winkler and token-Jaccard (handles both ``jdoe``↔``jdoe`` and
    ``John Q Doe``↔``Doe, John``) tempered by an n-gram floor."""
    na = norm.normalize_text(a, casefold=True)
    nb = norm.normalize_text(b, casefold=True)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    jw = jaro_winkler(na, nb)
    tj = token_jaccard(na, nb)
    ng = ngram_cosine(na, nb)
    return max(jw, tj, ng)


# --------------------------------------------------------------------------- #
# Multi-factor entity similarity                                               #
# --------------------------------------------------------------------------- #

@dataclass
class Signal:
    """One contributing similarity signal with its raw value and weight."""
    name: str
    raw: float           # [0, 1] similarity for this signal
    weight: float        # relative importance
    detail: str = ""

    @property
    def contribution(self) -> float:
        return self.raw * self.weight

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "raw": round(self.raw, 4),
                "weight": self.weight, "contribution": round(self.contribution, 4),
                "detail": self.detail}


@dataclass
class SimilarityResult:
    """Explainable output of comparing two entities.

    ``score`` is in [0, 1]: the weighted mean of the fired signals, promoted to
    ~1.0 when any *hard* identifier matches. ``signals`` is the full breakdown.
    """
    a_id: str
    b_id: str
    score: float = 0.0
    hard_match: bool = False
    signals: List[Signal] = field(default_factory=list)

    @property
    def percent(self) -> float:
        return round(self.score * 100.0, 1)

    def explanation(self) -> str:
        if not self.signals:
            return "no comparable signals"
        parts = [f"{s.name}={s.raw:.2f}(w{s.weight})" for s in self.signals
                 if s.raw > 0]
        tag = " [HARD MATCH]" if self.hard_match else ""
        return f"score={self.percent}%{tag} :: " + ", ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "a_id": self.a_id, "b_id": self.b_id,
            "score": round(self.score, 4), "percent": self.percent,
            "hard_match": self.hard_match,
            "signals": [s.to_dict() for s in self.signals],
        }


# Default relative weights. Hard identifiers are listed for documentation but
# handled by the hard-match short-circuit rather than the weighted mean.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "display_name": 3.0,
    "username": 4.0,
    "username_core": 2.0,
    "email": 5.0,            # (also a hard identifier)
    "email_domain": 1.5,
    "website": 3.0,
    "avatar_hash": 5.0,      # (also a hard identifier)
    "organization": 2.5,
    "timezone": 1.0,
    "language": 1.0,
    "bio": 2.0,
    "hashtags": 1.5,
    "shared_links": 2.5,
    "wallet": 6.0,           # (also a hard identifier)
    "certificate": 6.0,      # (also a hard identifier)
    "phone": 5.0,            # (also a hard identifier)
    "dns_record": 2.0,
}

# Metadata keys that, when byte-identical between two entities, are treated as
# near-conclusive on their own.
_HARD_IDENTIFIER_KEYS = ("avatar_sha256", "avatar_phash", "wallet",
                         "certificate_fingerprint", "pgp_fingerprint")


class SimilarityEngine:
    """Score how likely two entities are the same real-world thing.

    Construct once (optionally with custom ``weights``) and call
    ``score`` / ``score_entities`` repeatedly. Stateless and thread-safe.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None, *,
                 hard_match_floor: float = 0.97):
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self.hard_match_floor = hard_match_floor

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _meta(e: Entity, *keys: str) -> str:
        for k in keys:
            v = e.metadata.get(k)
            if v:
                return str(v)
        return ""

    def _w(self, name: str) -> float:
        return self.weights.get(name, 1.0)

    # -- public API -------------------------------------------------------- #

    def score_entities(self, a: Entity, b: Entity) -> SimilarityResult:
        """Full comparison of two entities across every applicable signal."""
        result = SimilarityResult(a_id=a.id, b_id=b.id)
        signals: List[Signal] = []

        # 1) Hard identifier equality — a single match is near-conclusive.
        hard = self._hard_identifier_match(a, b)
        if hard:
            result.hard_match = True
            signals.append(Signal(hard[0], 1.0, self._w(hard[0]) or 6.0,
                                   detail=f"identical {hard[1]}"))

        # 2) Same-type primary value comparison.
        if a.type == b.type and a.normalized and b.normalized:
            if a.normalized == b.normalized:
                signals.append(Signal("primary_value", 1.0, 6.0, "identical normalized value"))
                result.hard_match = True
            else:
                sim = self._primary_similarity(a, b)
                if sim > 0:
                    signals.append(Signal("primary_value", sim, 3.0,
                                          f"{a.type.value} value similarity"))

        # 3) Soft metadata signals (present on both sides only).
        signals.extend(self._soft_signals(a, b))

        # 4) Alias / handle overlap across the two entities.
        alias_sig = self._alias_overlap(a, b)
        if alias_sig:
            signals.append(alias_sig)

        result.signals = [s for s in signals if s.raw > 0]
        result.score = self._combine(result.signals, result.hard_match)
        return result

    # Backwards-friendly alias
    score = score_entities

    # -- signal computation ------------------------------------------------ #

    def _hard_identifier_match(self, a: Entity, b: Entity):
        for key in _HARD_IDENTIFIER_KEYS:
            va, vb = a.metadata.get(key), b.metadata.get(key)
            if va and vb and str(va).lower() == str(vb).lower():
                return (key.split("_")[0], key)   # e.g. ("avatar", "avatar_sha256")
        # wallet / certificate can also be the primary value of a typed entity
        if a.type == b.type and a.type in (EntityType.WALLET, EntityType.CERTIFICATE):
            if a.normalized and a.normalized == b.normalized:
                return (a.type.value, "primary")
        return None

    def _primary_similarity(self, a: Entity, b: Entity) -> float:
        t = a.type
        if t == EntityType.USERNAME:
            core = 1.0 if norm.username_core(a.value) == norm.username_core(b.value) else 0.0
            return max(jaro_winkler(a.normalized, b.normalized), core * 0.85)
        if t in (EntityType.PERSON, EntityType.ORGANIZATION):
            return best_name_similarity(a.value, b.value)
        if t in (EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.WEBSITE):
            return levenshtein_ratio(a.normalized, b.normalized)
        if t == EntityType.EMAIL:
            return 1.0 if norm.canonical_email(a.value) == norm.canonical_email(b.value) else 0.0
        return levenshtein_ratio(a.normalized, b.normalized)

    def _soft_signals(self, a: Entity, b: Entity) -> List[Signal]:
        out: List[Signal] = []

        def add(name: str, va: str, vb: str, fn) -> None:
            if va and vb:
                raw = fn(va, vb)
                if raw > 0:
                    out.append(Signal(name, raw, self._w(name)))

        add("display_name",
            self._meta(a, "display_name", "name", "full_name"),
            self._meta(b, "display_name", "name", "full_name"),
            best_name_similarity)

        add("bio",
            norm.normalize_text(self._meta(a, "bio", "description", "about"), casefold=True),
            norm.normalize_text(self._meta(b, "bio", "description", "about"), casefold=True),
            lambda x, y: ngram_cosine(x, y, n=3))

        add("organization",
            self._meta(a, "organization", "org", "company"),
            self._meta(b, "organization", "org", "company"),
            best_name_similarity)

        add("website",
            norm.canonical_url(self._meta(a, "website", "url", "blog")),
            norm.canonical_url(self._meta(b, "website", "url", "blog")),
            lambda x, y: 1.0 if x == y else levenshtein_ratio(x, y))

        add("email_domain",
            norm.email_domain(self._meta(a, "email")),
            norm.email_domain(self._meta(b, "email")),
            lambda x, y: 1.0 if x == y else 0.0)

        # equality-style soft signals
        for name, keys in (("timezone", ("timezone", "tz")),
                           ("language", ("language", "lang", "locale"))):
            va, vb = self._meta(a, *keys), self._meta(b, *keys)
            if va and vb:
                out.append(Signal(name, 1.0 if va.lower() == vb.lower() else 0.0,
                                  self._w(name)))

        # collection-overlap signals
        for name, keys in (("hashtags", ("hashtags", "tags")),
                           ("shared_links", ("links", "urls"))):
            va = self._as_list(a, keys)
            vb = self._as_list(b, keys)
            if va and vb:
                out.append(Signal(name, jaccard(va, vb), self._w(name)))

        return out

    @staticmethod
    def _as_list(e: Entity, keys) -> List[str]:
        for k in keys:
            v = e.metadata.get(k)
            if isinstance(v, (list, tuple, set)):
                return [str(x).lower() for x in v]
            if isinstance(v, str) and v:
                return [t.strip().lower() for t in v.replace(",", " ").split()]
        return []

    def _alias_overlap(self, a: Entity, b: Entity) -> Optional[Signal]:
        aa = {norm.canonical_username(x) for x in ({a.value} | a.aliases)}
        bb = {norm.canonical_username(x) for x in ({b.value} | b.aliases)}
        aa.discard(""); bb.discard("")
        if aa and bb and (aa & bb):
            return Signal("alias_overlap", 1.0, 3.0,
                          detail=f"shared handle(s): {sorted(aa & bb)[:3]}")
        return None

    def _combine(self, signals: List[Signal], hard_match: bool) -> float:
        if not signals:
            return 0.0
        total_w = sum(s.weight for s in signals)
        if total_w <= 0:
            return 0.0
        weighted = sum(s.contribution for s in signals) / total_w
        if hard_match:
            # Promote toward certainty but never fabricate a full 1.0 — leave
            # headroom that the confidence engine can erode with contradictions.
            return max(weighted, self.hard_match_floor)
        return min(weighted, 0.95)   # soft signals alone never assert identity
