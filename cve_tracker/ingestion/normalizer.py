"""
cve_tracker.ingestion.normalizer — per-source record hygiene before merge.

A single-source record from an adapter is already close to normalized, but this
pass makes the guarantees the rest of the pipeline relies on:

  * severity is a canonical :class:`Severity` value (or UNKNOWN), derived from
    CVSS when a source gave a score but no word (rule §8) — never invented
  * display CVSS scalars are populated from the source's own scores
  * internal lists are de-duplicated and scores clamped to [0,10]
  * initial provenance is stamped so the merger has a trust anchor

It mutates and returns the record. It does NOT reach across sources — that is
the deduplicator's job.
"""

from __future__ import annotations

from ..enums import Severity
from ..models import CVERecord, ProvenancedValue
from ..constants import SOURCE_TRUST, MAX_REFERENCES_STORE, MAX_PRODUCTS_STORE
from ..enrichment import cvss as cvss_engine
from ..enrichment.exploit_status import from_references
from ..utils import now_epoch, dedupe_preserve_order
from .parser import clamp_score, normalize_severity_string


def _trust(source: str) -> int:
    return SOURCE_TRUST.get(source, SOURCE_TRUST.get("other", 40))


def normalize_record(record: CVERecord) -> CVERecord:
    source = record.sources[0].source if record.sources else "other"

    # Clamp every CVSS score and drop impossible ones.
    clean_scores = []
    for s in record.cvss_scores:
        s.base_score = clamp_score(s.base_score)
        clean_scores.append(s)
    record.cvss_scores = clean_scores

    # Choose display CVSS from this source's scores.
    primary = cvss_engine.pick_primary(record.cvss_scores)
    if primary is not None:
        record.cvss_score = primary.base_score
        record.cvss_version = primary.version
        record.cvss_vector = primary.vector
        if record.cvss_score is not None:
            record.provenance["cvss_score"] = ProvenancedValue(
                value=record.cvss_score, source=source, trust=_trust(source),
                observed_at=now_epoch())

    # Severity: prefer an explicit CVSS-derived band; else a source word; else
    # keep whatever is set (UNKNOWN by default). Never fabricate.
    if primary is not None and primary.base_severity and primary.base_severity != Severity.UNKNOWN.value:
        record.severity = primary.base_severity
    elif record.cvss_score is not None:
        record.severity = Severity.from_cvss_score(
            record.cvss_score, version=record.cvss_version or "3.1").value
    else:
        record.severity = normalize_severity_string(record.severity)
    if record.severity and record.severity != Severity.UNKNOWN.value:
        record.provenance.setdefault("severity", ProvenancedValue(
            value=record.severity, source=source, trust=_trust(source),
            observed_at=now_epoch()))

    # De-duplicate/trim internal lists.
    record.aliases = dedupe_preserve_order(record.aliases)
    if len(record.references) > MAX_REFERENCES_STORE:
        record.references = record.references[:MAX_REFERENCES_STORE]
    if len(record.products) > MAX_PRODUCTS_STORE:
        record.products = record.products[:MAX_PRODUCTS_STORE]

    # Pre-merge exploit maturity from references (KEV folds in during merge).
    if not record.in_kev:
        record.exploit_maturity = from_references(record.references)

    return record
