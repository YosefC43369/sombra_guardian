"""
blueteam/dac/service.py — Detection-as-Code orchestration.

Compiles rules from the repository into the :class:`RuleEngine`, drives the
lifecycle state machine, versions rule bodies as a tamper-evident hash chain (and
seals each change to the injected ledger port), and offers lint/test/backtest.
Depends only on ports + the pure engine/lifecycle — no sqlite/telegram here.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from .domain import CompiledRule, RuleError, compile_rule, lint_regex, parse_condition
from .lifecycle import (DISABLED, SHADOW, CANARY, ENABLED, bump_version,
                        validate_transition, version_hash, LifecycleError, verify_chain)
from .matcher import RuleEngine, RuleHit


class RuleRepository(Protocol):
    def list_rules(self) -> List[Dict[str, Any]]: ...
    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]: ...
    def upsert_rule(self, rec: Dict[str, Any]) -> None: ...
    def delete_rule(self, rule_id: str) -> bool: ...
    def set_state(self, rule_id: str, state: str, canary_chats: List[int],
                  updated_by: Optional[int], now: float) -> None: ...
    def add_version(self, rule_id: str, version: str, body: str, sha256: str,
                    author: Optional[int], notes: str, now: float) -> None: ...
    def list_versions(self, rule_id: str) -> List[Dict[str, Any]]: ...
    def get_version(self, rule_id: str, version: str) -> Optional[Dict[str, Any]]: ...
    def latest_version_hash(self, rule_id: str) -> str: ...
    def record_hit(self, rule_id: str, chat_id: Optional[int], user_id: Optional[int],
                   mode: str, now: float) -> None: ...
    def recent_hits(self, rule_id: str, limit: int) -> List[Dict[str, Any]]: ...
    def hit_stats(self, since: float) -> Dict[str, int]: ...


class DacService:
    def __init__(self, repo: RuleRepository, *, clock: Callable[[], float] = time.time,
                 metrics=None, emit: Optional[Callable[[Any], None]] = None,
                 sealer: Optional[Callable[[str, dict], str]] = None,
                 max_ast_nodes: int = 500, per_rule_budget_us: int = 2000):
        self._repo = repo
        self._clock = clock
        self._metrics = metrics
        self._emit = emit or (lambda e: None)
        self._sealer = sealer            # (kind, payload) -> receipt; optional
        self._max_nodes = max_ast_nodes
        self._engine = RuleEngine(clock=clock, metrics=metrics,
                                  per_rule_budget_us=per_rule_budget_us)
        self.reload()

    @property
    def engine(self) -> RuleEngine:
        return self._engine

    # ---------------- compile / load ----------------
    def _compile_all(self) -> Tuple[List[CompiledRule], Dict[str, str], Dict[str, tuple]]:
        compiled, modes, canary = [], {}, {}
        for rec in self._repo.list_rules():
            body = self._version_body(rec["rule_id"])
            if body is None:
                continue
            try:
                cr = compile_rule(body, max_nodes=self._max_nodes)
            except RuleError:
                if self._metrics:
                    self._metrics.incr("bt_dac_compile_error", rule=rec["rule_id"])
                continue
            compiled.append(cr)
            modes[cr.rule_id] = rec.get("state", DISABLED)
            cc = rec.get("canary_chats") or []
            canary[cr.rule_id] = tuple(cc)
        return compiled, modes, canary

    def _version_body(self, rule_id: str) -> Optional[dict]:
        rec = self._repo.get_rule(rule_id)
        if not rec:
            return None
        ver = self._repo.get_version(rule_id, rec.get("version", ""))
        if ver is None:
            versions = self._repo.list_versions(rule_id)
            ver = versions[-1] if versions else None
        if ver is None:
            return None
        body = ver["body"]
        if isinstance(body, str):
            import json
            try:
                return json.loads(body)
            except ValueError:
                return None
        return body

    def reload(self) -> int:
        compiled, modes, canary = self._compile_all()
        self._engine.set_rules(compiled, modes, canary)
        if self._metrics:
            self._metrics.gauge("bt_dac_active_rules", self._engine.active_count())
        return len(compiled)

    # ---------------- evaluate ----------------
    def evaluate(self, record: Dict[str, Any], *, chat_id: Optional[int] = None,
                 record_hits: bool = True) -> List[RuleHit]:
        hits = self._engine.evaluate(record, chat_id=chat_id)
        if record_hits and hits:
            now = self._clock()
            for h in hits:
                try:
                    self._repo.record_hit(h.rule_id, chat_id, record.get("user_id"),
                                          h.mode, now)
                except Exception:
                    pass
        return hits

    # ---------------- lint / test / backtest ----------------
    def lint(self, body: dict) -> Dict[str, Any]:
        problems: List[str] = []
        detection = body.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            problems.append("missing detection.condition")
        else:
            try:
                parse_condition(str(detection["condition"]), max_nodes=self._max_nodes)
            except RuleError as exc:
                problems.append(f"condition: {exc}")
            for name, sel in detection.items():
                if name == "condition" or not isinstance(sel, dict):
                    continue
                for k, v in sel.items():
                    if "re" in k.split("|")[1:]:
                        for pat in (v if isinstance(v, list) else [v]):
                            ok, reason = lint_regex(str(pat))
                            if not ok:
                                problems.append(f"{name}.{k}: {reason}")
        if not body.get("id"):
            problems.append("missing id")
        try:
            compile_rule(body, max_nodes=self._max_nodes)
        except RuleError as exc:
            problems.append(f"compile: {exc}")
        return {"ok": not problems, "problems": problems}

    def test(self, body: dict, record: Dict[str, Any]) -> Dict[str, Any]:
        lint = self.lint(body)
        if not lint["ok"]:
            return {"ok": False, "problems": lint["problems"], "matched": False}
        cr = compile_rule(body, max_nodes=self._max_nodes)
        return {"ok": True, "matched": cr.match(record),
                "literals": cr.literals, "problems": []}

    def backtest(self, rule_id: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        body = self._version_body(rule_id)
        if body is None:
            return {"ok": False, "matches": 0, "total": len(records)}
        cr = compile_rule(body, max_nodes=self._max_nodes)
        matches = sum(1 for r in records if cr.match(r))
        return {"ok": True, "rule_id": rule_id, "matches": matches,
                "total": len(records), "rate": round(matches / max(1, len(records)), 4)}

    # ---------------- lifecycle / versioning ----------------
    def import_rule(self, body: dict, *, actor: Optional[int] = None,
                    notes: str = "import") -> Dict[str, Any]:
        lint = self.lint(body)
        if not lint["ok"]:
            return {"ok": False, "problems": lint["problems"]}
        cr = compile_rule(body, max_nodes=self._max_nodes)
        now = self._clock()
        existing = self._repo.get_rule(cr.rule_id)
        prev_version = existing.get("version", "") if existing else ""
        new_version = bump_version(prev_version) if existing else "1.0.0"
        prev_hash = self._repo.latest_version_hash(cr.rule_id)
        import json
        body_json = json.dumps(body, sort_keys=True, ensure_ascii=False)
        sha = version_hash(body, prev_hash)
        self._repo.add_version(cr.rule_id, new_version, body_json, sha, actor, notes, now)
        self._repo.upsert_rule({
            "rule_id": cr.rule_id, "title": cr.title, "level": cr.level,
            "logsource": cr.logsource, "version": new_version,
            "state": existing.get("state", DISABLED) if existing else DISABLED,
            "canary_chats": existing.get("canary_chats", []) if existing else [],
            "tags": cr.tags, "cooldown_s": cr.cooldown_s,
            "dedupe_field": cr.dedupe_field, "updated_at": now, "updated_by": actor})
        self._seal("rule_version", {"rule_id": cr.rule_id, "version": new_version, "sha256": sha})
        self.reload()
        return {"ok": True, "rule_id": cr.rule_id, "version": new_version, "sha256": sha}

    def set_state(self, rule_id: str, new_state: str, *, actor: Optional[int] = None,
                  canary_chats: Optional[List[int]] = None) -> Dict[str, Any]:
        rec = self._repo.get_rule(rule_id)
        if not rec:
            return {"ok": False, "error": "unknown rule"}
        old = rec.get("state", DISABLED)
        try:
            validate_transition(old, new_state)
        except LifecycleError as exc:
            return {"ok": False, "error": str(exc)}
        cc = canary_chats if canary_chats is not None else rec.get("canary_chats", [])
        self._repo.set_state(rule_id, new_state, cc, actor, self._clock())
        self._seal("rule_state", {"rule_id": rule_id, "from": old, "to": new_state})
        self._emit(_state_changed(rule_id, old, new_state, actor))
        self.reload()
        return {"ok": True, "rule_id": rule_id, "state": new_state}

    def shadow(self, rid, **k): return self.set_state(rid, SHADOW, **k)
    def canary(self, rid, chats, **k): return self.set_state(rid, CANARY, canary_chats=chats, **k)
    def enable(self, rid, **k): return self.set_state(rid, ENABLED, **k)
    def disable(self, rid, **k): return self.set_state(rid, DISABLED, **k)

    def rollback(self, rule_id: str, to_version: str, *, actor: Optional[int] = None
                 ) -> Dict[str, Any]:
        ver = self._repo.get_version(rule_id, to_version)
        if ver is None:
            return {"ok": False, "error": "version not found"}
        import json
        try:
            body = json.loads(ver["body"]) if isinstance(ver["body"], str) else ver["body"]
        except ValueError:
            return {"ok": False, "error": "corrupt version body"}
        return self.import_rule(body, actor=actor, notes=f"rollback to {to_version}")

    def history(self, rule_id: str) -> Dict[str, Any]:
        versions = self._repo.list_versions(rule_id)
        ok, bad = verify_chain(versions)
        return {"rule_id": rule_id, "versions": versions, "chain_ok": ok, "first_bad": bad}

    def delete_rule(self, rule_id: str) -> bool:
        ok = self._repo.delete_rule(rule_id)
        if ok:
            self.reload()
        return ok

    # ---------------- introspection ----------------
    def list_rules(self) -> List[Dict[str, Any]]:
        return self._repo.list_rules()

    def show_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        rec = self._repo.get_rule(rule_id)
        if not rec:
            return None
        rec = dict(rec)
        rec["body"] = self._version_body(rule_id)
        return rec

    def stats(self) -> Dict[str, Any]:
        rules = self._repo.list_rules()
        by_state: Dict[str, int] = {}
        for r in rules:
            by_state[r.get("state", DISABLED)] = by_state.get(r.get("state", DISABLED), 0) + 1
        return {"total": len(rules), "by_state": by_state,
                "active": self._engine.active_count(),
                "breakers_open": list(self._engine.breaker_states().keys()),
                "hits_24h": self._repo.hit_stats(self._clock() - 86400)}

    def load_pack(self, rules: List[dict], *, actor: Optional[int] = None,
                  activate: bool = False) -> Dict[str, Any]:
        loaded, failed = 0, []
        for body in rules:
            res = self.import_rule(body, actor=actor, notes="starter pack")
            if res.get("ok"):
                loaded += 1
                if activate:
                    self.set_state(res["rule_id"], SHADOW, actor=actor)
            else:
                failed.append(body.get("id", "?"))
        return {"loaded": loaded, "failed": failed}

    def _seal(self, kind: str, payload: dict) -> None:
        if self._sealer is None:
            return
        try:
            self._sealer(kind, payload)
        except Exception:
            if self._metrics:
                self._metrics.incr("bt_dac_seal_error")


def _state_changed(rule_id: str, old: str, new: str, actor: Optional[int]):
    from ..platform.events import RuleStateChanged
    return RuleStateChanged(rule_id=rule_id, old_state=old, new_state=new, actor=actor)


__all__ = ["DacService", "RuleRepository"]
