"""
threat_actor_intelligence.correlation.alias_resolution — careful alias handling.

The single most dangerous operation in a CTI system is merging two names into one
identity. Vendor naming diverges (APT29 / Cozy Bear / Midnight Blizzard /
Nobelium / UNC2452) and *colliding* aliases are common (multiple "DEV-" and
"UNC" placeholders). So this resolver **never merges automatically**. It:

  * normalizes names deterministically (case, punctuation, common prefixes);
  * builds an exact alias index for O(1) confident equivalence;
  * scores fuzzy candidates (token-set + sequence similarity) and only *suggests*
    a merge above a configurable threshold, always with the evidence that would
    justify it and a required human-review flag.

A suggestion is a ``MergeCandidate`` carrying both objects' ids, the matched
name, the similarity breakdown and the shared corroborating evidence — never a
mutation. Merging is an explicit, evidence-gated action taken elsewhere.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Common naming prefixes/suffixes that carry no discriminating power on their own.
_STOPWORDS = {"apt", "group", "team", "gang", "the", "aka", "unc", "dev",
              "ta", "actor", "threat"}
_PREFIX_RE = re.compile(r"^(apt|ta|unc|dev|g|fin|temp)[-\s]?\d+$", re.IGNORECASE)


def normalize_name(name: str) -> str:
    s = (name or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    s = re.sub(r"\s+", " ", s)
    return s


def _tokens(name: str) -> Set[str]:
    return {t for t in normalize_name(name).split() if t}


def token_set_ratio(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    inter = ta & tb
    union = ta | tb
    return len(inter) / len(union)


def sequence_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, normalize_name(a), normalize_name(b)).ratio()


def similarity(a: str, b: str) -> Tuple[float, Dict[str, float]]:
    """Blended name similarity in [0,1] with its breakdown.

    A designator like ``APT29`` vs ``APT28`` is deliberately kept *low*: the
    token set is identical-ish but the digits differ, so we penalize numeric
    mismatch heavily to avoid the classic APT-number collision."""
    ts = token_set_ratio(a, b)
    sr = sequence_ratio(a, b)
    na, nb = normalize_name(a), normalize_name(b)
    # numeric guard: if both are designators (apt\d+, unc\d+) with different
    # numbers, collapse similarity.
    da = re.findall(r"\d+", na)
    db = re.findall(r"\d+", nb)
    numeric_penalty = 0.0
    if da and db and da != db and _PREFIX_RE.match(na.replace(" ", "")) \
            and _PREFIX_RE.match(nb.replace(" ", "")):
        numeric_penalty = 0.6
    score = max(0.0, (0.55 * ts + 0.45 * sr) - numeric_penalty)
    return round(score, 4), {"token_set": round(ts, 4), "sequence": round(sr, 4),
                             "numeric_penalty": numeric_penalty}


@dataclass
class MergeCandidate:
    left_id: str
    right_id: str
    matched_left: str
    matched_right: str
    score: float
    breakdown: Dict[str, float] = field(default_factory=dict)
    shared_evidence: List[str] = field(default_factory=list)
    requires_review: bool = True
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"left_id": self.left_id, "right_id": self.right_id,
                "matched_left": self.matched_left, "matched_right": self.matched_right,
                "score": round(self.score, 4), "breakdown": self.breakdown,
                "shared_evidence": list(self.shared_evidence),
                "requires_review": self.requires_review, "reason": self.reason}


class AliasIndex:
    """Exact alias → object-id index for confident equivalence lookups."""

    def __init__(self) -> None:
        self._index: Dict[str, Set[str]] = {}
        self._names: Dict[str, List[str]] = {}   # object_id -> [names]

    def add(self, object_id: str, names: Iterable[str]) -> None:
        for name in names:
            norm = normalize_name(name)
            if not norm:
                continue
            self._index.setdefault(norm, set()).add(object_id)
            self._names.setdefault(object_id, [])
            if name not in self._names[object_id]:
                self._names[object_id].append(name)

    def objects_for(self, name: str) -> Set[str]:
        return set(self._index.get(normalize_name(name), set()))

    def collisions(self) -> List[Tuple[str, List[str]]]:
        """Aliases mapped to more than one object — merge candidates by exact
        name (still require review; colliding placeholders are real)."""
        out = []
        for norm, ids in self._index.items():
            if len(ids) > 1 and norm not in _STOPWORDS:
                out.append((norm, sorted(ids)))
        return sorted(out)

    def names_for(self, object_id: str) -> List[str]:
        return list(self._names.get(object_id, []))


class AliasResolver:
    def __init__(self, *, threshold: float = 0.86):
        self.threshold = threshold

    def suggest(self, objects: Sequence[Tuple[str, List[str], Set[str]]]
                ) -> List[MergeCandidate]:
        """Given ``(object_id, names, evidence_provider_set)`` tuples, return
        merge candidates. Exact alias collisions are always suggested; fuzzy
        matches above threshold are suggested when corroborated by ≥1 shared
        evidence provider, which strengthens (never replaces) the name signal."""
        index = AliasIndex()
        ev: Dict[str, Set[str]] = {}
        for oid, names, providers in objects:
            index.add(oid, names)
            ev[oid] = set(providers or set())

        candidates: Dict[Tuple[str, str], MergeCandidate] = {}

        # 1) exact alias collisions
        for norm, ids in index.collisions():
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    key = tuple(sorted((ids[i], ids[j])))
                    shared = sorted(ev.get(ids[i], set()) & ev.get(ids[j], set()))
                    candidates[key] = MergeCandidate(
                        left_id=key[0], right_id=key[1],
                        matched_left=norm, matched_right=norm, score=1.0,
                        breakdown={"exact_alias": 1.0}, shared_evidence=shared,
                        reason=f"shared alias '{norm}'")

        # 2) fuzzy name similarity across distinct objects
        items = [(oid, names) for oid, names, _ in objects]
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                oid_a, names_a = items[i]
                oid_b, names_b = items[j]
                if oid_a == oid_b:
                    continue
                key = tuple(sorted((oid_a, oid_b)))
                if key in candidates:
                    continue
                best = (0.0, "", "", {})
                for na in names_a:
                    for nb in names_b:
                        sc, br = similarity(na, nb)
                        if sc > best[0]:
                            best = (sc, na, nb, br)
                if best[0] >= self.threshold:
                    shared = sorted(ev.get(oid_a, set()) & ev.get(oid_b, set()))
                    if not shared:
                        # name-only fuzzy match: still surface but mark weak
                        reason = (f"fuzzy name match '{best[1]}'~'{best[2]}' "
                                  f"(no shared source)")
                    else:
                        reason = (f"fuzzy name match '{best[1]}'~'{best[2]}' "
                                  f"+ shared sources {shared}")
                    candidates[key] = MergeCandidate(
                        left_id=key[0], right_id=key[1], matched_left=best[1],
                        matched_right=best[2], score=best[0], breakdown=best[3],
                        shared_evidence=shared, reason=reason)
        return sorted(candidates.values(), key=lambda c: -c.score)


__all__ = ["normalize_name", "similarity", "token_set_ratio", "sequence_ratio",
           "MergeCandidate", "AliasIndex", "AliasResolver"]
