"""
behavioral_intelligence.social.reply_network — directed public reply graph
(spec §22).

Builds the reply graph (A replied to B) and reports in-degree, out-degree,
reciprocity, conversation depth and activity concentration (Gini of out-degree).
Relationship labels are deliberately absent — replying to someone is an observed
public act, not evidence of any social tie.
"""

from __future__ import annotations

from typing import Sequence

from ..models.observation import Observation
from ..models.behavior import InteractionNetwork
from ..content.thread_engine import analyze_threads
from . import mention_network


def _gini(values: Sequence[float]) -> float:
    """Gini coefficient of a non-negative distribution (0=equal, 1=concentrated)."""
    xs = sorted(v for v in values if v >= 0)
    n = len(xs)
    if n == 0 or sum(xs) == 0:
        return 0.0
    cum = 0.0
    for i, x in enumerate(xs, 1):
        cum += i * x
    return (2 * cum) / (n * sum(xs)) - (n + 1) / n


def build_reply_network(observations: Sequence[Observation], entity_id: str = ""
                        ) -> InteractionNetwork:
    net = mention_network.build_network(observations, entity_id, kind="reply")
    # activity concentration + conversation depth added to communities slot for
    # convenience (they are graph-level derived metrics, not relationship claims)
    thread = analyze_threads(observations)
    out_deg = list(net.node_out_degree.values())
    net.communities.append({
        "metric": "reply_graph_summary",
        "out_degree_gini": round(_gini(out_deg), 3),
        "mean_conversation_depth": round(thread.mean_depth, 2),
        "max_conversation_depth": thread.max_depth,
        "distinct_repliers": len(net.node_out_degree),
        "distinct_recipients": len(net.node_in_degree),
    })
    return net
