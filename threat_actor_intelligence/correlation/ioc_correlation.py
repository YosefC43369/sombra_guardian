"""
threat_actor_intelligence.correlation.ioc_correlation.

Correlates IOCs strictly through *documented public evidence*, per the spec
signals: shared campaign, shared malware, shared report, shared infrastructure,
shared certificate, shared ASN, shared domain, shared IP. Two IOCs are linked
only when they co-occur under one of these signals; the relationship names the
signal and carries the union of the two IOCs' evidence.

This never *infers* a link from value similarity alone — an IOC being on the
same /24 as another is a shared-infrastructure signal only when a source placed
them together or the infra correlation established the overlap.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from ..models.ioc import IOC, IOCType
from .base import CorrelationResult, build_relationship, correlation_assertion


def _signal_keys(ioc: IOC) -> List[Tuple[str, str]]:
    """The evidence-backed grouping keys for an IOC (signal_name, value)."""
    keys: List[Tuple[str, str]] = []
    if ioc.campaign:
        keys.append(("campaign", ioc.campaign.lower()))
    if ioc.malware:
        keys.append(("malware", ioc.malware.lower()))
    if ioc.actor:
        keys.append(("actor", ioc.actor.lower()))
    for ref in ioc.evidence.refs:
        if ref.external_id:
            keys.append(("report", ref.external_id))
        elif ref.source_url:
            keys.append(("report", ref.source_url))
    for tag in ioc.tags:
        if tag.lower().startswith("asn:"):
            keys.append(("asn", tag.lower()))
        elif tag.lower().startswith("cert:"):
            keys.append(("certificate", tag.lower()))
    return keys


class IOCCorrelator:
    def __init__(self, *, min_confidence: float = 0.0):
        self.min_confidence = min_confidence

    def correlate(self, iocs: Sequence[IOC],
                  *, now: Optional[float] = None) -> CorrelationResult:
        result = CorrelationResult()
        key_to_idx: Dict[Tuple[str, str], List[int]] = defaultdict(list)
        for idx, ioc in enumerate(iocs):
            for key in _signal_keys(ioc):
                key_to_idx[key].append(idx)

        pair_signals: Dict[tuple, List[str]] = defaultdict(list)
        for (signal, _val), idxs in key_to_idx.items():
            uniq = sorted(set(idxs))
            if len(uniq) < 2:
                continue
            for i in range(len(uniq)):
                for j in range(i + 1, len(uniq)):
                    pair_signals[(uniq[i], uniq[j])].append(signal)

        for (a, b), signals in pair_signals.items():
            ia, ib = iocs[a], iocs[b]
            evidence = list(ia.evidence.refs) + list(ib.evidence.refs)
            uniq_signals = sorted(set(signals))
            weight = round(min(1.0, 0.4 + 0.2 * len(uniq_signals)), 4)
            rel = build_relationship(
                src_type="ioc", src_id=ia.id, rel_type="associated_with",
                dst_type="ioc", dst_id=ib.id,
                signal="shared " + ", ".join(uniq_signals),
                evidence=evidence, now=now, weight=weight)
            if rel.score >= self.min_confidence:
                result.add_relationship(rel)

        if result.relationships:
            result.assertions.append(correlation_assertion(
                f"{len(result.relationships)} IOC association(s) via shared "
                f"campaign/malware/report/infrastructure.", "CORRELATED",
                result.relationships))
        return result

    def group_by_signal(self, iocs: Sequence[IOC]) -> Dict[str, Dict[str, List[str]]]:
        """Return {signal: {value: [ioc_id,...]}} for reporting/pivot views."""
        out: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        for ioc in iocs:
            for signal, val in _signal_keys(ioc):
                out[signal][val].append(ioc.id)
        return {s: {v: sorted(set(ids)) for v, ids in vals.items() if len(ids) > 1}
                for s, vals in out.items()}


__all__ = ["IOCCorrelator"]
