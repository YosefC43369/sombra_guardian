"""
behavioral_intelligence.content.thread_engine — public thread reconstruction
(spec §18).

Reconstructs conversation threads from ``thread_id`` and ``in_reply_to`` links,
then reports per-thread size, depth (longest reply chain) and participants, plus
corpus-level averages. Depth is computed over the observed public posts only —
missing intermediate posts truncate a chain, which the engine notes rather than
hallucinating structure it did not see.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation


@dataclass
class Thread:
    thread_id: str = ""
    root: str = ""
    size: int = 0
    depth: int = 1
    participants: List[str] = field(default_factory=list)
    start: float = 0.0
    end: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return {"thread_id": self.thread_id, "root": self.root, "size": self.size,
                "depth": self.depth, "participants": self.participants,
                "start": self.start, "end": self.end}


@dataclass
class ThreadAnalysis:
    threads: List[Thread] = field(default_factory=list)
    thread_count: int = 0
    mean_size: float = 0.0
    mean_depth: float = 0.0
    max_depth: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {"thread_count": self.thread_count,
                "mean_size": round(self.mean_size, 2),
                "mean_depth": round(self.mean_depth, 2),
                "max_depth": self.max_depth,
                "threads": [t.to_dict() for t in self.threads[:50]]}


def _chain_depth(post_id: str, children: Dict[str, List[str]],
                 memo: Dict[str, int]) -> int:
    if post_id in memo:
        return memo[post_id]
    kids = children.get(post_id, [])
    if not kids:
        memo[post_id] = 1
        return 1
    d = 1 + max(_chain_depth(k, children, memo) for k in kids)
    memo[post_id] = d
    return d


def analyze_threads(observations: Sequence[Observation]) -> ThreadAnalysis:
    # group by thread; fall back to in_reply_to roots when thread_id absent
    by_thread: Dict[str, List[Observation]] = defaultdict(list)
    for o in observations:
        tid = o.thread_id or o.in_reply_to or (o.observation_id if o.thread_id == "" and
                                               o.in_reply_to == "" else "")
        if o.thread_id:
            by_thread[o.thread_id].append(o)
        elif o.in_reply_to:
            by_thread[f"reply:{o.in_reply_to}"].append(o)

    threads: List[Thread] = []
    for tid, posts in by_thread.items():
        if len(posts) < 2:
            continue
        # build child map by in_reply_to (post id keyed by observation_id/source_url)
        id_of = {}
        for p in posts:
            id_of[p.observation_id] = p
        children: Dict[str, List[str]] = defaultdict(list)
        roots: List[str] = []
        for p in posts:
            parent = p.in_reply_to
            if parent and parent in id_of:
                children[parent].append(p.observation_id)
            else:
                roots.append(p.observation_id)
        memo: Dict[str, int] = {}
        depth = max((_chain_depth(r, children, memo) for r in roots), default=1)
        ts = [p.timestamp for p in posts if p.has_time]
        threads.append(Thread(
            thread_id=tid, root=roots[0] if roots else "",
            size=len(posts), depth=depth,
            participants=sorted({p.account_id for p in posts if p.account_id}),
            start=min(ts) if ts else 0.0, end=max(ts) if ts else 0.0))

    result = ThreadAnalysis(threads=sorted(threads, key=lambda t: t.size,
                                           reverse=True))
    result.thread_count = len(threads)
    if threads:
        result.mean_size = sum(t.size for t in threads) / len(threads)
        result.mean_depth = sum(t.depth for t in threads) / len(threads)
        result.max_depth = max(t.depth for t in threads)
    return result
