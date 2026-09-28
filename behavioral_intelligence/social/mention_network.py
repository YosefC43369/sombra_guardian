"""
behavioral_intelligence.social.mention_network — directed public mention graph
(spec §21).

Builds A → B edges from observed public mentions, with per-edge count, kind
breakdown, first/last-seen, platform spread and sample evidence URLs. Also
computes in/out degree and reciprocity for the resulting graph. The engine
records that A publicly mentioned B; it never labels the relationship
(friendship, employment, association) — that would be inference the data cannot
support (spec §22).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

from ..models.observation import Observation
from ..models.behavior import InteractionEdge, InteractionNetwork


def build_edges(observations: Sequence[Observation], *,
                kind: str = "mention") -> List[InteractionEdge]:
    """Aggregate directed edges from an actor to each account they mention.
    ``kind`` selects the source field: 'mention' uses ``mentions``; 'reply' uses
    ``in_reply_to``."""
    agg: Dict[Tuple[str, str], InteractionEdge] = {}
    for o in observations:
        src = o.account_id
        if not src:
            continue
        if kind == "reply":
            targets = [o.in_reply_to] if o.in_reply_to else []
        else:
            targets = list(o.mentions)
        for tgt in targets:
            tgt = str(tgt).strip().lstrip("@").lower()
            if not tgt or tgt == src.lower():
                continue
            key = (src, tgt)
            edge = agg.get(key)
            if edge is None:
                edge = InteractionEdge(source=src, target=tgt)
                agg[key] = edge
            edge.count += 1
            edge.kinds[kind] = edge.kinds.get(kind, 0) + 1
            if o.platform and o.platform not in edge.platforms:
                edge.platforms.append(o.platform)
            if o.has_time:
                edge.first_seen = (o.timestamp if edge.first_seen == 0
                                   else min(edge.first_seen, o.timestamp))
                edge.last_seen = max(edge.last_seen, o.timestamp)
            if o.source_url and len(edge.sample_urls) < 3:
                edge.sample_urls.append(o.source_url)
    return sorted(agg.values(), key=lambda e: e.count, reverse=True)


def degrees(edges: Sequence[InteractionEdge]) -> Tuple[Dict[str, int], Dict[str, int]]:
    out_deg: Dict[str, int] = defaultdict(int)
    in_deg: Dict[str, int] = defaultdict(int)
    for e in edges:
        out_deg[e.source] += 1
        in_deg[e.target] += 1
    return dict(in_deg), dict(out_deg)


def reciprocity(edges: Sequence[InteractionEdge]) -> float:
    """Fraction of directed edges whose reverse also exists (0..1)."""
    present = {(e.source, e.target) for e in edges}
    if not present:
        return 0.0
    mutual = sum(1 for (a, b) in present if (b, a) in present)
    return mutual / len(present)


def build_network(observations: Sequence[Observation], entity_id: str = "",
                  *, kind: str = "mention") -> InteractionNetwork:
    edges = build_edges(observations, kind=kind)
    in_deg, out_deg = degrees(edges)
    return InteractionNetwork(
        entity_id=entity_id, edges=edges,
        node_in_degree=in_deg, node_out_degree=out_deg,
        reciprocity=reciprocity(edges))
