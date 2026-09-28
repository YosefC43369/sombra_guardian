"""
threat_actor_intelligence.correlation.infrastructure_correlation.

Links infrastructure nodes (and, through them, campaigns/actors) by *documented
overlap*: a shared certificate fingerprint, a shared resolving IP, a shared ASN,
a shared hosting provider, a shared domain. Each node exposes ``overlap_keys()``;
two nodes sharing ≥ ``min_signals`` keys are linked with a
``RelationType.OVERLAPS`` relationship whose signal names exactly which keys
matched. This is the correlation that lets separate campaigns be tied together
without asserting they are the same actor.

Certificate and IP overlaps are weighted higher than a bare shared hosting
provider (which is weak — many benign tenants share a CDN), so the relationship
weight reflects the strength of the overlap.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Sequence

from ..models.infrastructure import Infrastructure
from .base import CorrelationResult, build_relationship, correlation_assertion

# Overlap-key strength (higher = more discriminating).
_KEY_WEIGHT = {"cert": 1.0, "ip": 0.85, "domain": 0.9, "asn": 0.5, "host": 0.35}


def _key_strength(key: str) -> float:
    return _KEY_WEIGHT.get(key.split(":", 1)[0], 0.4)


class InfrastructureCorrelator:
    def __init__(self, *, min_signals: int = 1, min_weight: float = 0.35):
        self.min_signals = min_signals
        self.min_weight = min_weight

    def correlate(self, nodes: Sequence[Infrastructure],
                  *, now: Optional[float] = None) -> CorrelationResult:
        result = CorrelationResult()
        # invert: overlap key -> node indices
        key_to_nodes: Dict[str, List[int]] = defaultdict(list)
        node_keys: List[set] = []
        for idx, node in enumerate(nodes):
            keys = set(node.overlap_keys())
            node_keys.append(keys)
            for k in keys:
                key_to_nodes[k].append(idx)

        # candidate pairs sharing at least one key
        pair_keys: Dict[tuple, List[str]] = defaultdict(list)
        for k, idxs in key_to_nodes.items():
            if len(idxs) < 2:
                continue
            for i in range(len(idxs)):
                for j in range(i + 1, len(idxs)):
                    a, b = idxs[i], idxs[j]
                    if a == b:
                        continue
                    pair_keys[tuple(sorted((a, b)))].append(k)

        for (a, b), shared in pair_keys.items():
            if len(shared) < self.min_signals:
                continue
            weight = round(min(1.0, sum(_key_strength(k) for k in shared)), 4)
            if weight < self.min_weight:
                continue
            na, nb = nodes[a], nodes[b]
            evidence = list(na.evidence.refs) + list(nb.evidence.refs)
            signal = "shared " + ", ".join(sorted(shared))
            rel = build_relationship(
                src_type="infrastructure", src_id=na.infra_id,
                rel_type="overlaps", dst_type="infrastructure", dst_id=nb.infra_id,
                signal=signal, evidence=evidence, now=now, weight=weight)
            result.add_relationship(rel)

        if result.relationships:
            result.assertions.append(correlation_assertion(
                f"{len(result.relationships)} infrastructure overlap link(s) found "
                f"across {len(nodes)} node(s).", "CORRELATED", result.relationships))
        return result

    def clusters(self, nodes: Sequence[Infrastructure],
                 *, now: Optional[float] = None) -> List[List[str]]:
        """Connected components over the overlap graph → infrastructure clusters
        (union-find). Returns lists of infra_ids."""
        parent: Dict[int, int] = {i: i for i in range(len(nodes))}

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            parent[find(x)] = find(y)

        res = self.correlate(nodes, now=now)
        id_to_idx = {n.infra_id: i for i, n in enumerate(nodes)}
        for rel in res.relationships:
            union(id_to_idx[rel.src_id], id_to_idx[rel.dst_id])
        comps: Dict[int, List[str]] = defaultdict(list)
        for i, n in enumerate(nodes):
            comps[find(i)].append(n.infra_id)
        return [sorted(v) for v in comps.values() if len(v) > 1]


__all__ = ["InfrastructureCorrelator"]
