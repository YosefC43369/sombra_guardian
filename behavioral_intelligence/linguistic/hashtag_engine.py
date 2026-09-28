"""
behavioral_intelligence.linguistic.hashtag_engine — hashtag tracking (spec §14).

Frequency, growth/decline trend (recent-half rate vs. earlier-half rate),
first/last-seen, co-occurring hashtags and platform spread. Hashtags come from
the observation's parsed ``hashtags`` list (already lower-cased, '#'-stripped).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Sequence, Set

from ..models.observation import Observation
from ..models.topic import Hashtag
from .. import util


def extract_hashtags(observations: Sequence[Observation], *, top_n: int = 25,
                     min_count: int = 1) -> List[Hashtag]:
    freq: Counter = Counter()
    first_seen: Dict[str, float] = {}
    last_seen: Dict[str, float] = {}
    platforms: Dict[str, Set[str]] = defaultdict(set)
    cooc: Dict[str, Counter] = defaultdict(Counter)

    timed = [o for o in observations if o.has_time]
    midpoint = 0.0
    if timed:
        lo = min(o.timestamp for o in timed)
        hi = max(o.timestamp for o in timed)
        midpoint = (lo + hi) / 2.0
    early: Counter = Counter()
    late: Counter = Counter()

    for o in observations:
        tags = o.hashtags
        for t in tags:
            freq[t] += 1
            if o.platform:
                platforms[t].add(o.platform)
            if o.has_time:
                first_seen[t] = min(first_seen.get(t, o.timestamp), o.timestamp)
                last_seen[t] = max(last_seen.get(t, o.timestamp), o.timestamp)
                (late if o.timestamp >= midpoint else early)[t] += 1
        for a in set(tags):
            for b in set(tags):
                if a != b:
                    cooc[a][b] += 1

    out: List[Hashtag] = []
    for tag, f in freq.items():
        if f < min_count:
            continue
        early_c, late_c = early.get(tag, 0), late.get(tag, 0)
        growth = util.safe_div(late_c - early_c, max(early_c, 1))
        trend = ("rising" if late_c > early_c * 1.25 else
                 ("declining" if late_c < early_c * 0.75 else "stable"))
        out.append(Hashtag(
            tag=tag, frequency=f, first_seen=first_seen.get(tag, 0.0),
            last_seen=last_seen.get(tag, 0.0), trend=trend, growth=growth,
            cooccurring=[c for c, _ in cooc[tag].most_common(5)],
            platforms=sorted(platforms.get(tag, set()))))
    out.sort(key=lambda h: h.frequency, reverse=True)
    return out[:top_n]
