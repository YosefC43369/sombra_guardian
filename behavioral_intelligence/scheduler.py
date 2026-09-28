"""
behavioral_intelligence.scheduler — periodic snapshots and the diff engine
(spec §45, §46).

Two responsibilities:
  * take periodic ``BehaviorProfile`` snapshots for an entity and persist them,
    so historical state is preserved for comparison;
  * diff two snapshots to surface what changed between them — new/removed
    accounts, domains, URLs, hashtags, topics, and shifts in language, activity
    rate and interaction volume.

The scheduler loop is async and cancellable; the diff engine is pure and can be
called on any two stored snapshots.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .storage.sqlite_store import SQLiteStore

logger = logging.getLogger("modbot.behavioral.scheduler")


@dataclass
class SnapshotDiff:
    entity_id: str = ""
    from_snapshot: int = 0
    to_snapshot: int = 0
    new_accounts: List[str] = field(default_factory=list)
    removed_accounts: List[str] = field(default_factory=list)
    new_domains: List[str] = field(default_factory=list)
    removed_domains: List[str] = field(default_factory=list)
    new_hashtags: List[str] = field(default_factory=list)
    removed_hashtags: List[str] = field(default_factory=list)
    new_topics: List[str] = field(default_factory=list)
    faded_topics: List[str] = field(default_factory=list)
    language_shift: Dict[str, Any] = field(default_factory=dict)
    activity_change: Dict[str, Any] = field(default_factory=dict)
    interaction_change: Dict[str, Any] = field(default_factory=dict)

    def has_changes(self) -> bool:
        return any([self.new_accounts, self.removed_accounts, self.new_domains,
                    self.removed_domains, self.new_hashtags, self.new_topics,
                    self.language_shift, self.faded_topics])

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


def _accounts(profile: Dict[str, Any]) -> set:
    inter = profile.get("interactions") or {}
    accts = set()
    for e in inter.get("edges", []):
        accts.add(e.get("source", ""))
        accts.add(e.get("target", ""))
    accts |= set(profile.get("platforms", []))
    return {a for a in accts if a}


def _domains(profile: Dict[str, Any]) -> set:
    return {d.get("domain", "") for d in profile.get("domains", []) if d.get("domain")}


def _hashtags(profile: Dict[str, Any]) -> set:
    return {h.get("tag", "") for h in profile.get("hashtags", []) if h.get("tag")}


def _topics(profile: Dict[str, Any]) -> set:
    evo = profile.get("topic_evolution") or {}
    terms = set()
    for period in evo.get("periods", []):
        for t in period.get("top_terms", []):
            terms.add(t[0] if isinstance(t, list) else t)
    return {t for t in terms if t}


def _dominant_language(profile: Dict[str, Any]) -> str:
    langs = (profile.get("languages") or {}).get("shares", {})
    return max(langs, key=langs.get) if langs else "und"


def _posts_per_day(profile: Dict[str, Any]) -> float:
    return (profile.get("activity") or {}).get("posts_per_day", 0.0)


def diff_snapshots(a: Dict[str, Any], b: Dict[str, Any], *,
                   from_id: int = 0, to_id: int = 0) -> SnapshotDiff:
    """Diff two profile snapshots (``a`` earlier, ``b`` later) → ``SnapshotDiff``."""
    diff = SnapshotDiff(entity_id=b.get("entity_id", a.get("entity_id", "")),
                        from_snapshot=from_id, to_snapshot=to_id)
    aa, ba = _accounts(a), _accounts(b)
    diff.new_accounts = sorted(ba - aa)
    diff.removed_accounts = sorted(aa - ba)

    ad, bd = _domains(a), _domains(b)
    diff.new_domains = sorted(bd - ad)
    diff.removed_domains = sorted(ad - bd)

    ah, bh = _hashtags(a), _hashtags(b)
    diff.new_hashtags = sorted(bh - ah)
    diff.removed_hashtags = sorted(ah - bh)

    at, bt = _topics(a), _topics(b)
    diff.new_topics = sorted(bt - at)
    diff.faded_topics = sorted(at - bt)

    la, lb = _dominant_language(a), _dominant_language(b)
    if la != lb:
        diff.language_shift = {"from": la, "to": lb}

    pa, pb = _posts_per_day(a), _posts_per_day(b)
    if pa or pb:
        diff.activity_change = {"from_per_day": round(pa, 3),
                                "to_per_day": round(pb, 3),
                                "relative": round(pb / pa, 3) if pa else None}

    ia = len((a.get("interactions") or {}).get("edges", []))
    ib = len((b.get("interactions") or {}).get("edges", []))
    if ia != ib:
        diff.interaction_change = {"from_edges": ia, "to_edges": ib}
    return diff


class SnapshotScheduler:
    def __init__(self, store: Optional[SQLiteStore] = None,
                 db_path: str = "behavioral_intelligence.db"):
        self.store = store or SQLiteStore(db_path)
        self._task: Optional[asyncio.Task] = None

    def take_snapshot(self, entity_id: str, profile_dict: Dict[str, Any],
                      label: str = "") -> int:
        return self.store.save_snapshot(entity_id, profile_dict, label=label)

    def diff_latest(self, entity_id: str) -> Optional[SnapshotDiff]:
        snaps = self.store.list_snapshots(entity_id)
        if len(snaps) < 2:
            return None
        a = self.store.get_snapshot(snaps[-2]["id"])
        b = self.store.get_snapshot(snaps[-1]["id"])
        if not a or not b:
            return None
        return diff_snapshots(a, b, from_id=snaps[-2]["id"], to_id=snaps[-1]["id"])

    async def run_periodic(self, entity_id: str, snapshot_fn, *,
                           interval_seconds: float = 86400.0,
                           max_iterations: Optional[int] = None) -> None:
        """Periodically call ``snapshot_fn(entity_id) -> dict`` and store the
        result. Cancellable; ``max_iterations`` bounds it for tests."""
        i = 0
        try:
            while max_iterations is None or i < max_iterations:
                try:
                    profile = snapshot_fn(entity_id)
                    if profile is not None:
                        self.take_snapshot(entity_id, profile)
                except Exception:
                    logger.exception("scheduled snapshot failed (non-fatal)")
                i += 1
                if max_iterations is not None and i >= max_iterations:
                    break
                await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:  # pragma: no cover
            logger.info("snapshot scheduler cancelled for %s", entity_id)
            raise

    def start(self, entity_id: str, snapshot_fn, *,
              interval_seconds: float = 86400.0) -> asyncio.Task:
        self._task = asyncio.ensure_future(
            self.run_periodic(entity_id, snapshot_fn,
                              interval_seconds=interval_seconds))
        return self._task

    def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
