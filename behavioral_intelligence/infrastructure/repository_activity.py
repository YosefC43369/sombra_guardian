"""
behavioral_intelligence.infrastructure.repository_activity — public repository
activity behaviour (spec §28 red-team footprint / §26 blue-team).

Summarises public version-control activity carried in observations
(``content_type`` COMMIT / RELEASE, or ``metadata['repo']``): commit cadence,
active repositories, release timing and the hour-of-day distribution of commits
(a common footprint signal). Read-only over already-public activity.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation, ContentType
from .. import util


@dataclass
class RepositoryActivity:
    repository: str = ""
    commits: int = 0
    releases: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    active_days: int = 0
    commits_per_active_day: float = 0.0
    hour_histogram: List[int] = field(default_factory=lambda: [0] * 24)
    languages: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {"repository": self.repository, "commits": self.commits,
                "releases": self.releases, "first_seen": self.first_seen,
                "last_seen": self.last_seen, "active_days": self.active_days,
                "commits_per_active_day": round(self.commits_per_active_day, 3),
                "hour_histogram": self.hour_histogram, "languages": self.languages}


def analyze_repository_activity(observations: Sequence[Observation]
                                ) -> List[RepositoryActivity]:
    groups: Dict[str, List[Observation]] = defaultdict(list)
    for o in observations:
        repo = o.metadata.get("repo") or o.metadata.get("repository")
        if repo:
            groups[str(repo)].append(o)
        elif o.content_type in (ContentType.COMMIT, ContentType.RELEASE):
            groups[o.account_id or o.platform or "unknown"].append(o)

    out: List[RepositoryActivity] = []
    for repo, obs in groups.items():
        act = RepositoryActivity(repository=repo)
        days = set()
        langs: Counter = Counter()
        for o in obs:
            if o.content_type == ContentType.RELEASE:
                act.releases += 1
            else:
                act.commits += 1
            if o.has_time:
                act.first_seen = (o.timestamp if act.first_seen == 0
                                  else min(act.first_seen, o.timestamp))
                act.last_seen = max(act.last_seen, o.timestamp)
                if o.timestamp_precision.supports_hour:
                    act.hour_histogram[o.hour_utc] += 1
                days.add(o.date_utc)
            lang = o.metadata.get("language") or o.language
            if lang:
                langs[str(lang)] += 1
        act.active_days = len(days)
        act.commits_per_active_day = util.safe_div(act.commits, max(len(days), 1))
        act.languages = dict(langs)
        out.append(act)
    out.sort(key=lambda a: a.commits + a.releases, reverse=True)
    return out
