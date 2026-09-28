"""
behavioral_intelligence.social.account_activity — per-account lifecycle and
change tracking (spec §25).

For each observed account: first/last activity, peak, rate, and observable
profile changes (username / avatar / bio) inferred from successive ``profile``
snapshots carried in observation metadata. Emits ``TimelineEvent`` and
``ChangePoint``-style records so the timeline engine can fold them in. Records
what changed and when; never why.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..models.observation import Observation, ContentType
from ..models.timeline import TimelineEvent, ChangeKind
from .. import util


@dataclass
class AccountLifecycle:
    account: str = ""
    platform: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    peak_at: float = 0.0
    total: int = 0
    posts_per_day: float = 0.0
    profile_changes: List[TimelineEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"account": self.account, "platform": self.platform,
                "first_seen": self.first_seen, "last_seen": self.last_seen,
                "peak_at": self.peak_at, "total": self.total,
                "posts_per_day": round(self.posts_per_day, 3),
                "profile_changes": [e.to_dict() for e in self.profile_changes]}


# metadata keys that describe a profile snapshot, and the change kind they map to
_PROFILE_FIELDS = {
    "username": ChangeKind.USERNAME, "display_name": ChangeKind.USERNAME,
    "avatar": ChangeKind.AVATAR, "avatar_hash": ChangeKind.AVATAR,
    "bio": ChangeKind.BIO, "description": ChangeKind.BIO,
}


def analyze_accounts(observations: Sequence[Observation]) -> List[AccountLifecycle]:
    groups: Dict[str, List[Observation]] = defaultdict(list)
    for o in observations:
        if o.account_id:
            groups[f"{o.platform}/{o.account_id}"].append(o)

    out: List[AccountLifecycle] = []
    for key, obs in groups.items():
        obs = sorted(obs, key=lambda o: o.timestamp if o.has_time else 0)
        timed = [o for o in obs if o.has_time]
        ts = [o.timestamp for o in timed]
        span = (ts[-1] - ts[0]) / util.DAY_SECONDS if len(ts) >= 2 else 0.0
        platform, account = (key.split("/", 1) + [""])[:2]
        life = AccountLifecycle(
            account=account, platform=platform,
            first_seen=ts[0] if ts else 0.0, last_seen=ts[-1] if ts else 0.0,
            total=len(obs), posts_per_day=util.safe_div(len(obs), max(span, 1.0)))

        # peak day
        daily: Dict[str, int] = defaultdict(int)
        for o in timed:
            daily[o.date_utc] += 1
        if daily:
            peak_date = max(daily, key=lambda k: daily[k])
            for o in timed:
                if o.date_utc == peak_date:
                    life.peak_at = o.timestamp
                    break

        life.profile_changes = _profile_changes(obs)
        out.append(life)
    out.sort(key=lambda a: a.total, reverse=True)
    return out


def _profile_changes(obs: Sequence[Observation]) -> List[TimelineEvent]:
    """Detect changes across successive profile snapshots in metadata."""
    events: List[TimelineEvent] = []
    last: Dict[str, str] = {}
    for o in obs:
        snapshot = o.metadata
        if o.content_type != ContentType.PROFILE and not any(
                k in snapshot for k in _PROFILE_FIELDS):
            continue
        for field_key, kind in _PROFILE_FIELDS.items():
            if field_key not in snapshot:
                continue
            new_val = str(snapshot[field_key])
            old_val = last.get(field_key)
            if old_val is not None and old_val != new_val:
                events.append(TimelineEvent(
                    at=o.timestamp, kind=kind.value,
                    label=f"{field_key} changed",
                    platform=o.platform,
                    detail={"from": old_val, "to": new_val},
                    evidence_id=o.evidence_id or o.observation_id))
            last[field_key] = new_val
    return events
