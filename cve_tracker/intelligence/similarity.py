"""
cve_tracker.intelligence.similarity — lightweight textual similarity.

Supports two jobs: (1) secondary de-duplication confidence — when two records
share a CVE id we already merge them, but when a source gives only a title/alias
this scores how likely two entries describe the same issue (rule §9 secondary
matching); (2) 'related CVEs' ranking by title overlap. Pure token math (Jaccard
+ a shared-identifier boost), no heavy NLP dependency.
"""

from __future__ import annotations

import re
from typing import List, Set

from ..models import CVERecord
from ..utils import extract_cve_ids, normalize_ghsa_id

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\-\.]+")
_STOP = {
    "the", "a", "an", "in", "of", "to", "and", "or", "for", "with", "via",
    "allows", "could", "may", "when", "this", "that", "is", "are", "be", "on",
    "by", "from", "vulnerability", "issue", "flaw", "cve", "attacker", "remote",
}


def tokenize(text: str) -> Set[str]:
    if not text:
        return set()
    return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP and len(t) > 2}


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def title_similarity(a: str, b: str) -> float:
    return jaccard(tokenize(a), tokenize(b))


def record_similarity(a: CVERecord, b: CVERecord) -> float:
    """Combined similarity in [0,1]. Same CVE id = 1.0. Otherwise blends title
    and shared aliases/references."""
    if a.cve_id and a.cve_id == b.cve_id:
        return 1.0
    # Shared alias (e.g. both map to the same GHSA) is a strong signal.
    aliases_a = {normalize_ghsa_id(x) or x for x in a.aliases}
    aliases_b = {normalize_ghsa_id(x) or x for x in b.aliases}
    if aliases_a & aliases_b:
        return 0.95

    title = title_similarity(a.title or a.description[:120], b.title or b.description[:120])
    refs_a = {r.url for r in a.references}
    refs_b = {r.url for r in b.references}
    ref_overlap = jaccard(refs_a, refs_b)
    vendor_overlap = jaccard(set(map(str.lower, a.vendors)), set(map(str.lower, b.vendors)))
    return round(0.6 * title + 0.25 * ref_overlap + 0.15 * vendor_overlap, 3)


def is_likely_same(a: CVERecord, b: CVERecord, *, threshold: float = 0.75) -> bool:
    return record_similarity(a, b) >= threshold


def rank_related(base: CVERecord, candidates: List[CVERecord], *, limit: int = 5) -> List[CVERecord]:
    """Rank candidates by similarity to ``base`` (excluding itself)."""
    scored = [
        (record_similarity(base, c), c)
        for c in candidates if c.cve_id != base.cve_id
    ]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for score, c in scored if score > 0.0][:limit]
