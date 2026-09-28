"""
blueteam/dac/matcher.py — the runtime detection engine (pure; stdlib only).

  * an **Aho-Corasick** automaton built from rule literals, used purely as a
    *prefilter*: a rule is only evaluated if one of its required literals appears
    in the text (rules with no literals are always evaluated), so N rules cost
    ~one linear scan + a handful of predicate calls, not N full scans;
  * **stateful aggregation** (count / distinct / sequence) over per-key
    time-window ring buffers (deques pruned to ``window_s``);
  * **per-rule circuit breaking**: a rule whose evaluation repeatedly blows its
    time budget is opened (skipped) until it cools down, so one pathological rule
    can't stall the pipeline (fail-open for detection);
  * **dedupe/cooldown** per (rule, chat, key) so one incident isn't reported
    dozens of times.

The engine holds a set of :class:`CompiledRule`; the service compiles/loads them.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from .domain import CompiledRule

# rule modes
DISABLED, SHADOW, CANARY, ENABLED = "disabled", "shadow", "canary", "enabled"


# ---------------- Aho-Corasick ----------------

class _ACNode:
    __slots__ = ("children", "fail", "outputs")

    def __init__(self):
        self.children: Dict[str, "_ACNode"] = {}
        self.fail: Optional["_ACNode"] = None
        self.outputs: List[str] = []       # literals ending here


class AhoCorasick:
    """Multi-pattern substring matcher. ``search`` returns the set of literals found."""

    def __init__(self, patterns: List[str]):
        self._root = _ACNode()
        self._empty = True
        for p in patterns:
            if p:
                self._insert(p)
                self._empty = False
        self._build()

    def _insert(self, pat: str) -> None:
        node = self._root
        for ch in pat:
            node = node.children.setdefault(ch, _ACNode())
        node.outputs.append(pat)

    def _build(self) -> None:
        q: Deque[_ACNode] = deque()
        for child in self._root.children.values():
            child.fail = self._root
            q.append(child)
        while q:
            cur = q.popleft()
            for ch, nxt in cur.children.items():
                q.append(nxt)
                f = cur.fail
                while f is not None and ch not in f.children:
                    f = f.fail
                nxt.fail = f.children[ch] if (f and ch in f.children) else self._root
                nxt.outputs += nxt.fail.outputs

    def search(self, text: str) -> set:
        if self._empty:
            return set()
        found = set()
        node = self._root
        for ch in text:
            while node is not None and ch not in node.children:
                node = node.fail
            node = node.children[ch] if (node and ch in node.children) else self._root
            if node.outputs:
                found.update(node.outputs)
        return found


# ---------------- aggregation state ----------------

class _AggWindow:
    """Per (rule,key) sliding window of (ts, value) for count/distinct/sequence."""

    __slots__ = ("events",)

    def __init__(self):
        self.events: Deque[Tuple[float, Any]] = deque()

    def add_and_prune(self, ts: float, value: Any, window_s: float) -> None:
        self.events.append((ts, value))
        cutoff = ts - window_s
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def count(self) -> int:
        return len(self.events)

    def distinct(self) -> int:
        return len({v for _t, v in self.events})


@dataclass
class RuleHit:
    rule_id: str
    title: str
    level: str
    mode: str
    attack: str = ""
    aggregated: bool = False
    detail: str = ""


@dataclass
class _RuleState:
    rule: CompiledRule
    mode: str = DISABLED
    canary_chats: Tuple[int, ...] = ()
    # circuit breaker
    slow_strikes: int = 0
    open_until: float = 0.0


class RuleEngine:
    def __init__(self, *, clock: Callable[[], float] = time.time, metrics=None,
                 per_rule_budget_us: int = 2000, slow_strikes_to_open: int = 5,
                 breaker_cooldown_s: float = 300.0):
        self._clock = clock
        self._metrics = metrics
        self._budget_us = per_rule_budget_us
        self._strikes_open = slow_strikes_to_open
        self._cooldown = breaker_cooldown_s
        self._states: Dict[str, _RuleState] = {}
        self._ac = AhoCorasick([])
        self._always: List[str] = []            # rule_ids with no literals
        self._agg: Dict[Tuple[str, Any], _AggWindow] = defaultdict(_AggWindow)
        self._cooldowns: Dict[Tuple[str, Optional[int], str], float] = {}

    # ---- membership / lifecycle ----
    def set_rules(self, rules: List[CompiledRule], modes: Dict[str, str],
                  canary: Optional[Dict[str, Tuple[int, ...]]] = None) -> None:
        canary = canary or {}
        self._states = {}
        for r in rules:
            self._states[r.rule_id] = _RuleState(
                rule=r, mode=modes.get(r.rule_id, DISABLED),
                canary_chats=tuple(canary.get(r.rule_id, ())))
        self._rebuild_ac()

    def _rebuild_ac(self) -> None:
        patterns: List[str] = []
        self._always = []
        for rid, st in self._states.items():
            if st.mode == DISABLED:
                continue
            if st.rule.literals:
                patterns.extend(st.rule.literals)
            else:
                self._always.append(rid)
        self._ac = AhoCorasick(sorted(set(patterns)))

    def active_count(self) -> int:
        return sum(1 for s in self._states.values() if s.mode != DISABLED)

    # ---- evaluation ----
    def evaluate(self, record: Dict[str, Any], *, chat_id: Optional[int] = None) -> List[RuleHit]:
        now = self._clock()
        text = str(record.get("text_lower") or record.get("text") or "").lower()
        present = self._ac.search(text) if text else set()

        # candidate rules: always-on + those whose literal appeared
        candidates: List[str] = list(self._always)
        for rid, st in self._states.items():
            if st.mode == DISABLED or not st.rule.literals:
                continue
            if any(lit in present for lit in st.rule.literals):
                candidates.append(rid)

        hits: List[RuleHit] = []
        for rid in candidates:
            st = self._states.get(rid)
            if st is None or st.mode == DISABLED:
                continue
            if st.open_until > now:                 # breaker open -> skip (fail-open)
                continue
            # canary: only fire in listed chats
            if st.mode == CANARY and chat_id is not None and chat_id not in st.canary_chats:
                continue
            hit = self._eval_one(st, record, chat_id, now)
            if hit is not None:
                hits.append(hit)
        return hits

    def _eval_one(self, st: _RuleState, record, chat_id, now) -> Optional[RuleHit]:
        rule = st.rule
        t0 = time.perf_counter()
        try:
            matched = rule.match(record)
        except Exception:
            matched = False
            if self._metrics:
                self._metrics.incr("bt_dac_rule_error", rule=rule.rule_id)
        elapsed_us = (time.perf_counter() - t0) * 1e6
        if self._metrics:
            self._metrics.observe("bt_dac_rule_us", elapsed_us)
        if elapsed_us > self._budget_us:
            st.slow_strikes += 1
            if st.slow_strikes >= self._strikes_open:
                st.open_until = now + self._cooldown
                st.slow_strikes = 0
                if self._metrics:
                    self._metrics.incr("bt_dac_breaker_open", rule=rule.rule_id)
        else:
            st.slow_strikes = max(0, st.slow_strikes - 1)

        if not matched:
            return None

        # aggregation gate
        aggregated = False
        detail = ""
        if rule.aggregation:
            fired, detail = self._aggregate(rule, record, chat_id, now)
            aggregated = True
            if not fired:
                return None

        # dedupe / cooldown
        if rule.cooldown_s > 0:
            key = self._dedupe_key(rule, record)
            ck = (rule.rule_id, chat_id, key)
            until = self._cooldowns.get(ck, 0.0)
            if until > now:
                return None
            self._cooldowns[ck] = now + rule.cooldown_s

        if self._metrics:
            self._metrics.incr("bt_dac_match", rule=rule.rule_id, mode=st.mode)
        return RuleHit(rule_id=rule.rule_id, title=rule.title, level=rule.level,
                       mode=st.mode, attack=rule.attack, aggregated=aggregated, detail=detail)

    def _aggregate(self, rule: CompiledRule, record, chat_id, now) -> Tuple[bool, str]:
        agg = rule.aggregation or {}
        atype = str(agg.get("type", "count")).lower()
        window_s = float(agg.get("window_s", 60) or 60)
        gte = float(agg.get("gte", agg.get("count", 1)) or 1)
        group_field = agg.get("group_by") or agg.get("by")
        field_val = record.get(agg.get("field")) if agg.get("field") else None
        group_key = (chat_id, record.get(group_field)) if group_field else chat_id
        win = self._agg[(rule.rule_id, group_key)]
        win.add_and_prune(now, field_val, window_s)
        if atype == "distinct":
            n = win.distinct()
        else:  # count / sequence collapse to windowed count of matches
            n = win.count()
        return (n >= gte, f"{atype}={n}/{int(gte)} ใน {int(window_s)}s")

    def _dedupe_key(self, rule: CompiledRule, record) -> str:
        if rule.dedupe_field:
            return str(record.get(rule.dedupe_field, ""))
        return ""

    def breaker_states(self) -> Dict[str, float]:
        now = self._clock()
        return {rid: st.open_until - now for rid, st in self._states.items()
                if st.open_until > now}


__all__ = ["RuleEngine", "RuleHit", "AhoCorasick", "DISABLED", "SHADOW", "CANARY", "ENABLED"]
