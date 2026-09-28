"""
blueteam/joinguard.py — Join Guard / Anti-Raid engine.

Watches ``chat_member`` join events and decides, per group, whether the group is
under a coordinated raid. Components:

  * :class:`JoinRateTracker` — an O(1)-per-event, memory-bounded adaptive baseline.
    A ring buffer of recent join timestamps gives the current joins-per-window; an
    EWMA of that rate provides mean/variance for a z-score. Cold-start uses an
    absolute threshold until enough history exists.
  * :class:`RaidStateMachine` — NORMAL → ELEVATED → RAID → COOLDOWN → NORMAL with
    **hysteresis** (separate up/down thresholds + minimum dwell time) so it does
    not flap. State is persisted via the store so a lockdown survives a restart.
  * name-signature clustering (skeleton similarity across recent joins), same
    invite-link surge, and join/leave churn — extra raid evidence, each an
    explainable :class:`~blueteam.models.Signal`.

The engine decides *what state we're in* and *what action a policy implies*
(challenge new joiners, lock down); the plugin performs the Telegram side-effects
(restrict, ban+unban, setChatPermissions) through wired services. The clock is
injectable so the state machine is unit-tested deterministically.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Tuple

from . import textkit as tk
from .models import Assessment, Signal


class RaidState(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    RAID = "RAID"
    COOLDOWN = "COOLDOWN"


@dataclass(frozen=True)
class JoinGuardParams:
    window_seconds: int = 60
    ewma_alpha: float = 0.3
    min_samples: int = 5              # before z-score is trusted
    z_elevated: float = 2.5
    z_raid: float = 4.0
    cold_elevated: int = 6            # joins/window during cold-start -> elevated
    cold_raid: int = 12               # joins/window during cold-start -> raid
    hard_raid: int = 20               # absolute joins/window -> raid regardless
    cooldown_rate: int = 3            # rate at/below which a raid starts cooling
    min_dwell_seconds: int = 30       # hysteresis: min time before de-escalating
    cluster_similarity: float = 0.9   # name-skeleton Jaro-Winkler for a cluster
    cluster_min: int = 3              # similar joins -> cluster signal
    buffer: int = 512
    max_chats: int = 2000


@dataclass(slots=True)
class _ChatWindow:
    joins: Deque = field(default_factory=lambda: deque(maxlen=512))     # timestamps
    names: Deque = field(default_factory=lambda: deque(maxlen=512))     # (skeleton, ts)
    invites: Deque = field(default_factory=lambda: deque(maxlen=512))   # (invite, ts)
    leaves: Deque = field(default_factory=lambda: deque(maxlen=512))    # timestamps
    ewma_mean: float = 0.0
    ewma_var: float = 0.0
    samples: int = 0


class JoinRateTracker:
    def __init__(self, params: JoinGuardParams):
        self.p = params
        self._chats: "OrderedDict[int, _ChatWindow]" = OrderedDict()

    def _window(self, chat_id: int) -> _ChatWindow:
        w = self._chats.get(chat_id)
        if w is None:
            mx = self.p.buffer
            w = _ChatWindow(joins=deque(maxlen=mx), names=deque(maxlen=mx),
                            invites=deque(maxlen=mx), leaves=deque(maxlen=mx))
            self._chats[chat_id] = w
        self._chats.move_to_end(chat_id)
        while len(self._chats) > self.p.max_chats:
            self._chats.popitem(last=False)
        return w

    def record_leave(self, chat_id: int, now: float) -> None:
        self._window(chat_id).leaves.append(now)

    def observe(self, chat_id: int, now: float, *, name_skeleton: str = "",
                invite: str = "") -> Dict[str, float]:
        """Record a join and return metrics: rate, zscore, cluster_size, churn,
        invite_surge. O(1) amortised (bounded deques)."""
        w = self._window(chat_id)
        cutoff = now - self.p.window_seconds
        w.joins.append(now)
        if name_skeleton:
            w.names.append((name_skeleton, now))
        if invite:
            w.invites.append((invite, now))

        rate = sum(1 for t in w.joins if t >= cutoff)

        # EWMA baseline of the rate (updated once per join; cheap).
        if w.samples == 0:
            w.ewma_mean = rate
            w.ewma_var = 0.0
        else:
            a = self.p.ewma_alpha
            delta = rate - w.ewma_mean
            w.ewma_mean += a * delta
            w.ewma_var = (1 - a) * (w.ewma_var + a * delta * delta)
        w.samples += 1

        std = w.ewma_var ** 0.5
        zscore = (rate - w.ewma_mean) / std if std > 1e-6 else 0.0

        # name-signature cluster within the window
        recent_names = [s for (s, t) in w.names if t >= cutoff and s]
        cluster_size = 0
        if name_skeleton:
            cluster_size = sum(
                1 for s in recent_names
                if tk.jaro_winkler(s, name_skeleton) >= self.p.cluster_similarity)

        # same-invite surge
        invite_surge = 0
        if invite:
            invite_surge = sum(1 for (iv, t) in w.invites if t >= cutoff and iv == invite)

        churn = sum(1 for t in w.leaves if t >= cutoff)
        return {"rate": rate, "zscore": zscore, "cluster_size": cluster_size,
                "invite_surge": invite_surge, "churn": churn,
                "baseline": w.ewma_mean, "samples": w.samples}


class RaidStateMachine:
    """Pure state machine with hysteresis; the caller persists the state."""

    def __init__(self, params: JoinGuardParams):
        self.p = params

    def next_state(self, current: RaidState, since: float, metrics: Dict[str, float],
                   now: float) -> Tuple[RaidState, bool]:
        """Return (new_state, changed). Escalation is immediate; de-escalation
        requires the rate to have fallen AND a minimum dwell time (hysteresis)."""
        rate = metrics["rate"]
        z = metrics["zscore"]
        samples = metrics["samples"]
        cluster = metrics.get("cluster_size", 0)
        cold = samples < self.p.min_samples

        raid_trigger = (rate >= self.p.hard_raid
                        or (cold and rate >= self.p.cold_raid)
                        or (not cold and z >= self.p.z_raid)
                        or cluster >= self.p.cluster_min * 2)
        elevated_trigger = (rate >= self.p.cold_elevated if cold
                            else z >= self.p.z_elevated) or cluster >= self.p.cluster_min

        dwell_ok = (now - since) >= self.p.min_dwell_seconds

        if current == RaidState.NORMAL:
            if raid_trigger:
                return RaidState.RAID, True
            if elevated_trigger:
                return RaidState.ELEVATED, True
            return current, False

        if current == RaidState.ELEVATED:
            if raid_trigger:
                return RaidState.RAID, True
            if not elevated_trigger and dwell_ok:
                return RaidState.NORMAL, True
            return current, False

        if current == RaidState.RAID:
            # only start cooling when the flood has clearly subsided + dwell
            if rate <= self.p.cooldown_rate and dwell_ok:
                return RaidState.COOLDOWN, True
            return current, False

        if current == RaidState.COOLDOWN:
            if raid_trigger:
                return RaidState.RAID, True
            if rate <= self.p.cooldown_rate and dwell_ok:
                return RaidState.NORMAL, True
            return current, False

        return current, False


@dataclass(slots=True)
class JoinDecision:
    state: RaidState
    changed: bool
    challenge_required: bool
    lockdown_required: bool
    assessment: Assessment
    metrics: Dict[str, float] = field(default_factory=dict)


class JoinGuard:
    def __init__(self, store=None, params: Optional[JoinGuardParams] = None,
                 clock=None):
        self.p = params or JoinGuardParams()
        self._store = store
        self._tracker = JoinRateTracker(self.p)
        self._sm = RaidStateMachine(self.p)
        self._clock = clock or time.time

    def record_leave(self, chat_id: int, now: Optional[float] = None) -> None:
        self._tracker.record_leave(chat_id, now if now is not None else self._clock())

    def observe_join(self, chat_id: int, *, display_name: str = "", username: str = "",
                     invite: str = "", now: Optional[float] = None) -> JoinDecision:
        now = now if now is not None else self._clock()
        skel = tk.skeleton(display_name or username or "")
        metrics = self._tracker.observe(chat_id, now, name_skeleton=skel, invite=invite)

        # current state (persisted; survives restart)
        if self._store is not None:
            row = self._store.get_raid_state(chat_id)
            cur = RaidState(row["state"]) if row["state"] in RaidState.__members__ else RaidState.NORMAL
            since = row.get("since") or now
        else:
            cur = RaidState.NORMAL
            since = now

        new_state, changed = self._sm.next_state(cur, since, metrics, now)

        if self._store is not None and (changed or cur == RaidState.NORMAL and new_state == RaidState.NORMAL):
            if changed:
                self._store.set_raid_state(chat_id, new_state.value,
                                           meta={"metrics": metrics}, since=now)

        a = self._build_assessment(chat_id, new_state, metrics)
        challenge_required = new_state in (RaidState.ELEVATED, RaidState.RAID)
        lockdown_required = new_state == RaidState.RAID
        return JoinDecision(state=new_state, changed=changed,
                            challenge_required=challenge_required,
                            lockdown_required=lockdown_required,
                            assessment=a, metrics=metrics)

    def _build_assessment(self, chat_id: int, state: RaidState,
                          metrics: Dict[str, float]) -> Assessment:
        a = Assessment("joinguard", subject=str(chat_id),
                       meta={"state": state.value, "metrics": metrics})
        rate = metrics["rate"]
        if metrics["zscore"] >= self.p.z_elevated or rate >= self.p.cold_elevated:
            a.add(Signal("join_rate_anomaly", min(40, int(10 + rate * 2)), "raid",
                         f"อัตราการเข้ากลุ่มสูงผิดปกติ ({rate} คน/{self.p.window_seconds}s, "
                         f"z={metrics['zscore']:.1f})", "T1498"))
        if metrics.get("cluster_size", 0) >= self.p.cluster_min:
            a.add(Signal("name_cluster", 30, "raid",
                         f"ชื่อผู้เข้าใหม่คล้ายกันเป็นชุด ({metrics['cluster_size']} คน)",
                         "T1136"))
        if metrics.get("invite_surge", 0) >= self.p.cluster_min:
            a.add(Signal("invite_surge", 20, "raid",
                         f"เข้าผ่านลิงก์เชิญเดียวกันพุ่งสูง ({metrics['invite_surge']} คน)"))
        if metrics.get("churn", 0) >= self.p.cold_elevated:
            a.add(Signal("join_leave_churn", 15, "raid",
                         f"เข้า-ออกถี่ผิดปกติ ({metrics['churn']} ครั้ง)"))
        return a
