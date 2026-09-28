"""
behavioral_intelligence.infrastructure.domain_activity — temporal behaviour of
domains referenced in public content (spec §16 / red-team footprint).

Complements ``content.domain_behavior`` (which counts domains) with the *timing*
of each domain's public appearance: first/last-seen, the reference cadence, and
whether a domain newly appeared or dropped out relative to a prior window. Useful
for spotting infrastructure a target began referencing (or stopped) at a point
in time. Passive: strings only, no resolution or fetching.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation
from ..content.domain_behavior import _domain_of
from .. import util


@dataclass
class DomainTimeline:
    domain: str = ""
    frequency: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    active_days: int = 0
    mean_interval_seconds: float = 0.0
    platforms: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"domain": self.domain, "frequency": self.frequency,
                "first_seen": self.first_seen, "last_seen": self.last_seen,
                "active_days": self.active_days,
                "mean_interval_seconds": round(self.mean_interval_seconds, 1),
                "platforms": self.platforms}


def analyze_domain_activity(observations: Sequence[Observation], *, top_n: int = 50
                            ) -> List[DomainTimeline]:
    times: Dict[str, List[float]] = defaultdict(list)
    platforms: Dict[str, set] = defaultdict(set)
    days: Dict[str, set] = defaultdict(set)
    for o in observations:
        for u in list(o.urls) + [f"http://{d}" for d in o.domains]:
            dom = _domain_of(u)
            if not dom:
                continue
            if o.has_time:
                times[dom].append(o.timestamp)
                days[dom].add(o.date_utc)
            if o.platform:
                platforms[dom].add(o.platform)

    out: List[DomainTimeline] = []
    for dom, ts in times.items():
        ts.sort()
        gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        out.append(DomainTimeline(
            domain=dom, frequency=len(ts),
            first_seen=ts[0] if ts else 0.0, last_seen=ts[-1] if ts else 0.0,
            active_days=len(days[dom]),
            mean_interval_seconds=util.mean(gaps) if gaps else 0.0,
            platforms=sorted(platforms[dom])))
    out.sort(key=lambda d: d.frequency, reverse=True)
    return out[:top_n]
