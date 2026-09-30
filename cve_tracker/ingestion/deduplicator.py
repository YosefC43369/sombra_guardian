"""
cve_tracker.ingestion.deduplicator — merge the same CVE across sources.

The same vulnerability arrives from NVD, CVE.org, CISA KEV, GitHub… each a
single-source :class:`CVERecord`. The merger folds them into ONE record keyed by
CVE id, *unioning* list facts (references/products/weaknesses/cvss/sources/
aliases) and choosing display scalars (cvss_score, severity) by source trust —
while keeping every source's value in provenance so nothing is silently
overwritten (rules §9, §55, §56).

Merging is associative and order-independent for the union parts; for the
trust-picked scalars the highest-trust source wins deterministically regardless
of arrival order.
"""

from __future__ import annotations

from typing import Dict, List

from ..constants import (
    SOURCE_TRUST,
    MAX_REFERENCES_STORE,
    MAX_PRODUCTS_STORE,
)
from ..enums import ExploitMaturity, Severity
from ..models import CVERecord, CVSSScore, ProvenancedValue
from ..enrichment.cwe import merge_weaknesses
from ..enrichment.cpe import merge_products
from ..enrichment.references import merge_references
from ..utils import dedupe_preserve_order, now_epoch


def _trust(source: str) -> int:
    return SOURCE_TRUST.get(source, SOURCE_TRUST.get("other", 40))


def _merge_cvss(scores: List[CVSSScore]) -> List[CVSSScore]:
    """De-duplicate CVSS scores by (version, source), keeping the most complete
    (has a numeric score, then a vector)."""
    by_key: Dict[tuple, CVSSScore] = {}
    for s in scores:
        key = (s.version, s.source)
        cur = by_key.get(key)
        if cur is None:
            by_key[key] = s
            continue
        cur_completeness = (cur.base_score is not None, bool(cur.vector))
        new_completeness = (s.base_score is not None, bool(s.vector))
        # Prefer a MORE complete score; on a tie prefer the later one, because
        # merge_two lays out `base + incoming` so the freshly-ingested value
        # comes last and should supersede a stored value from the same source
        # that changed (e.g. a CVSS re-score 7.5 → 9.8).
        if new_completeness >= cur_completeness:
            by_key[key] = s
    return list(by_key.values())


def _choose_scalar(record: CVERecord, field: str, candidates: List[tuple]) -> None:
    """candidates: list of (value, source). Pick highest-trust non-empty and
    record provenance for the field. Store ALL candidates in provenance? We
    store the winner here; the full per-source CVSS list already preserves the
    rest, so provenance carries the chosen value + its source for display like
    'CVSS 8.8 (source: NVD)'."""
    best = None
    best_trust = -1
    for value, source in candidates:
        if value in (None, "", Severity.UNKNOWN.value):
            continue
        t = _trust(source)
        if t > best_trust:
            best = (value, source, t)
            best_trust = t
    if best is not None:
        setattr(record, field, best[0])
        record.provenance[field] = ProvenancedValue(
            value=best[0], source=best[1], trust=best[2], observed_at=now_epoch())


def merge_two(base: CVERecord, incoming: CVERecord) -> CVERecord:
    """Merge ``incoming`` into ``base`` (mutating and returning base)."""
    if not base.title and incoming.title:
        base.title = incoming.title
    # Prefer the longer/description from the higher-trust source for text.
    _merge_text(base, incoming)

    # earliest publication, latest modification
    base.published_at = _min_opt(base.published_at, incoming.published_at)
    base.last_modified_at = _max_opt(base.last_modified_at, incoming.last_modified_at)
    base.first_seen_at = min(base.first_seen_at or now_epoch(),
                             incoming.first_seen_at or now_epoch())

    # union list facts
    base.cvss_scores = _merge_cvss(base.cvss_scores + incoming.cvss_scores)
    base.weaknesses = merge_weaknesses(base.weaknesses, incoming.weaknesses)
    base.products = merge_products(base.products, incoming.products)[:MAX_PRODUCTS_STORE]
    base.references = merge_references(base.references, incoming.references)[:MAX_REFERENCES_STORE]
    base.aliases = dedupe_preserve_order(base.aliases + incoming.aliases)

    # sources (newest fetch first)
    base.sources = _merge_sources(base.sources + incoming.sources)

    # KEV: a positive KEV from any source wins (it is authoritative-for-presence)
    if incoming.in_kev and not base.in_kev:
        base.kev = incoming.kev
    elif incoming.in_kev and base.in_kev:
        # keep the one with a date_added
        if not base.kev.date_added and incoming.kev.date_added:
            base.kev = incoming.kev

    # exploit maturity: strongest wins
    base.exploit_maturity = _stronger_maturity(base.exploit_maturity, incoming.exploit_maturity)

    # external provenance (e.g. EPSS): carry over any key the base lacks, and
    # take the fresher one for keys both hold. The display scalars
    # (severity/cvss_score) are recomputed below, so they are excluded here.
    _display_keys = {"severity", "cvss_score"}
    for key, pv in incoming.provenance.items():
        if key in _display_keys:
            continue
        cur = base.provenance.get(key)
        if cur is None or pv.observed_at >= cur.observed_at:
            base.provenance[key] = pv

    # display scalars by trust
    _choose_scalar(base, "severity", [
        (base.severity, _dominant_source(base)),
        (incoming.severity, _dominant_source(incoming)),
    ])
    _recompute_display_cvss(base)

    return base


def _merge_text(base: CVERecord, incoming: CVERecord) -> None:
    if not base.description and incoming.description:
        base.description = incoming.description
        return
    if incoming.description and _dominant_trust(incoming) > _dominant_trust(base):
        # higher-trust source's description wins the display slot
        if len(incoming.description) >= 40:
            base.description = incoming.description


def _recompute_display_cvss(record: CVERecord) -> None:
    """Choose the display cvss_score/version/vector from the merged score list
    by (source trust, spec recency)."""
    if not record.cvss_scores:
        return
    version_rank = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}

    def key(s: CVSSScore):
        return (
            1 if s.base_score is not None else 0,
            _trust(s.source),
            version_rank.get(s.version, 0),
        )

    best = max(record.cvss_scores, key=key)
    if best.base_score is not None:
        record.cvss_score = best.base_score
        record.cvss_version = best.version
        record.cvss_vector = best.vector
        record.provenance["cvss_score"] = ProvenancedValue(
            value=best.base_score, source=best.source, trust=_trust(best.source),
            observed_at=now_epoch())
        if best.base_severity and best.base_severity != Severity.UNKNOWN.value:
            record.severity = best.base_severity


def _merge_sources(sources):
    seen = {}
    for s in sorted(sources, key=lambda x: x.fetched_at, reverse=True):
        seen.setdefault(s.source, s)
    return list(seen.values())


def _dominant_source(record: CVERecord) -> str:
    if not record.sources:
        return "other"
    return max(record.sources, key=lambda s: _trust(s.source)).source


def _dominant_trust(record: CVERecord) -> int:
    return _trust(_dominant_source(record))


def _stronger_maturity(a: str, b: str) -> str:
    rank = {
        ExploitMaturity.UNKNOWN.value: 0, ExploitMaturity.NONE.value: 1,
        ExploitMaturity.REFERENCED.value: 2, ExploitMaturity.PUBLIC_POC.value: 3,
        ExploitMaturity.CONFIRMED.value: 4,
    }
    return a if rank.get(a, 0) >= rank.get(b, 0) else b


def _min_opt(a, b):
    vals = [v for v in (a, b) if v is not None]
    return min(vals) if vals else None


def _max_opt(a, b):
    vals = [v for v in (a, b) if v is not None]
    return max(vals) if vals else None


def dedupe_batch(records: List[CVERecord]) -> List[CVERecord]:
    """Collapse a batch (possibly containing the same CVE from several sources)
    into one merged record per CVE id. Preserves first-seen order of ids."""
    by_id: Dict[str, CVERecord] = {}
    order: List[str] = []
    for rec in records:
        cid = rec.cve_id
        if cid not in by_id:
            by_id[cid] = rec
            order.append(cid)
        else:
            merge_two(by_id[cid], rec)
    return [by_id[cid] for cid in order]
