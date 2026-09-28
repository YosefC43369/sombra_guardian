"""
behavioral_intelligence.content.domain_behavior — domain-sharing behaviour
(spec §16).

Aggregates the domains that appear in public posts: frequency, URL count per
domain, shortener usage, first/last-seen, platform spread, and the transitions
between windows (which domains newly appeared and which disappeared). Uses a
small effective-TLD heuristic to fold ``a.b.example.co.uk`` down to
``example.co.uk`` without pulling in the full Public Suffix List.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Sequence, Set
from urllib.parse import urlsplit

from ..models.observation import Observation
from ..models.topic import DomainStat
from .url_behavior import _SHORTENERS, normalize_url

# Multi-label public suffixes we fold on (a pragmatic subset of the PSL).
_MULTI_TLD = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp", "co.th",
    "in.th", "ac.th", "com.au", "net.au", "org.au", "com.br", "com.cn",
    "co.kr", "co.in", "co.id", "com.sg", "com.my", "com.tr",
}


def registrable_domain(host: str) -> str:
    """Fold a hostname to its registrable domain using the multi-TLD subset."""
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in _MULTI_TLD:
        return ".".join(parts[-3:]) if len(parts) >= 3 else host
    if last3 in _MULTI_TLD:
        return ".".join(parts[-4:]) if len(parts) >= 4 else host
    return last2


def _domain_of(url: str) -> str:
    norm = normalize_url(url)
    if not norm:
        return ""
    return registrable_domain(urlsplit(norm).hostname or "")


def analyze_domains(observations: Sequence[Observation], *, top_n: int = 50
                    ) -> List[DomainStat]:
    freq: Counter = Counter()
    url_counts: Dict[str, Set[str]] = defaultdict(set)
    first_seen: Dict[str, float] = {}
    last_seen: Dict[str, float] = {}
    platforms: Dict[str, Set[str]] = defaultdict(set)

    for o in observations:
        seen_domains = set()
        for u in list(o.urls) + [f"http://{d}" for d in o.domains]:
            dom = _domain_of(u)
            if not dom:
                continue
            seen_domains.add(dom)
            url_counts[dom].add(normalize_url(u))
            if o.platform:
                platforms[dom].add(o.platform)
            if o.has_time:
                first_seen[dom] = min(first_seen.get(dom, o.timestamp), o.timestamp)
                last_seen[dom] = max(last_seen.get(dom, o.timestamp), o.timestamp)
        for dom in seen_domains:
            freq[dom] += 1

    out: List[DomainStat] = []
    for dom, f in freq.most_common(top_n):
        out.append(DomainStat(
            domain=dom, frequency=f, url_count=len(url_counts[dom]),
            is_shortener=dom in _SHORTENERS,
            first_seen=first_seen.get(dom, 0.0), last_seen=last_seen.get(dom, 0.0),
            platforms=sorted(platforms.get(dom, set()))))
    return out


def domain_transitions(early: Sequence[Observation], late: Sequence[Observation]
                       ) -> Dict[str, List[str]]:
    """Compare two windows: which registrable domains newly appeared in ``late``
    and which present in ``early`` disappeared (spec §16)."""
    def domset(obs: Sequence[Observation]) -> Set[str]:
        s: Set[str] = set()
        for o in obs:
            for u in list(o.urls) + [f"http://{d}" for d in o.domains]:
                d = _domain_of(u)
                if d:
                    s.add(d)
        return s
    early_set, late_set = domset(early), domset(late)
    return {"appeared": sorted(late_set - early_set),
            "disappeared": sorted(early_set - late_set),
            "retained": sorted(early_set & late_set)}
