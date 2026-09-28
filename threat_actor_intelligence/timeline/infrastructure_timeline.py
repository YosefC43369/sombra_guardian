"""
threat_actor_intelligence.timeline.infrastructure_timeline.

Chronology of an infrastructure node's observed lifetime: first/last seen, and
each evidence citation that dated an observation of it. Useful for spotting when
a C2 domain was stood up and when it went quiet, strictly from dated public
observations.
"""

from __future__ import annotations

from typing import List, Sequence

from ..models.infrastructure import Infrastructure
from .base import Timeline, TimelineEvent


class InfrastructureTimelineBuilder:
    def build(self, node: Infrastructure) -> Timeline:
        tl = Timeline(subject_type="infrastructure", subject_id=node.infra_id)
        if node.first_seen:
            tl.add(TimelineEvent(at=node.first_seen, kind="first_seen",
                                 label=f"{node.value} first observed",
                                 detail={"role": node.role, "asn": node.asn},
                                 sources=node.evidence.providers()))
        if node.last_seen and node.last_seen != node.first_seen:
            tl.add(TimelineEvent(at=node.last_seen, kind="last_seen",
                                 label=f"{node.value} last observed",
                                 sources=node.evidence.providers()))
        for ref in node.evidence.refs:
            if ref.observed_at:
                tl.add(TimelineEvent(
                    at=ref.observed_at, kind="reported",
                    label=f"Observed via {ref.provider}"[:120],
                    detail={"url": ref.source_url}, sources=[ref.provider]))
        return tl

    def merged(self, nodes: Sequence[Infrastructure], *, subject_id: str = ""
               ) -> Timeline:
        tl = Timeline(subject_type="infrastructure_cluster", subject_id=subject_id)
        for node in nodes:
            for ev in self.build(node).events:
                ev.detail = {**ev.detail, "node": node.value}
                tl.add(ev)
        return tl


__all__ = ["InfrastructureTimelineBuilder"]
