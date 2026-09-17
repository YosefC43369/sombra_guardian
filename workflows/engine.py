"""
workflows/engine.py — the Workflow Automation Engine.

Flow:  Event -> match enabled workflows by trigger -> evaluate conditions
       -> loop-guard + dedup checks -> run actions (retry/timeout) -> persist
       execution + logs + audit -> emit any follow-up events (with depth+1).

Execution safety
----------------
* Every run gets a unique ``execution_id`` (uuid).
* ``correlation_id`` threads an event and all it triggers together.
* ``max_execution_time`` caps a run via asyncio.wait_for -> TIMEOUT state.
* ``max_retries`` retries failed actions with exponential backoff.
* Idempotency / dedup: a ``dedup_key`` + ``cooldown`` window suppresses a
  repeat run of the same workflow for the same logical event.
* Loop prevention: ``max_depth`` on the event chain stops
  incident.created -> update -> incident.updated -> ... recursing forever.

The engine is async (the bot runs on asyncio) but has zero Telegram or
feature-module imports — actions reach those through injected Services.
Persistence is optional: pass ``db_path=None`` for a pure in-memory engine
(handy in tests); with a path it writes to the ``wf_*`` tables migration
0001 creates.
"""

import time
import uuid
import json
import asyncio
import logging
import sqlite3
from typing import Dict, List, Optional

from .models import Event, WorkflowState, ExecutionRecord
from .conditions import evaluate_all
from .actions import ActionRegistry, Services

logger = logging.getLogger("modbot.workflows.engine")


# ---------------- Workflow definition ----------------

class WorkflowDefinition:
    """A single automation: trigger + conditions + ordered actions + safety
    knobs. Built from a dict (JSON/YAML/py) via ``from_dict``."""

    def __init__(self, name: str, trigger: str, actions: List[str],
                 conditions: Optional[List[dict]] = None, enabled: bool = True,
                 description: str = "", max_retries: int = 0,
                 timeout_seconds: float = 30.0, cooldown_seconds: float = 0.0,
                 max_depth: int = 5, dedup_fields: Optional[List[str]] = None,
                 retry_backoff_seconds: float = 0.5):
        if not name:
            raise ValueError("workflow needs a name")
        if not trigger:
            raise ValueError(f"workflow {name!r} needs a trigger")
        if not actions:
            raise ValueError(f"workflow {name!r} needs at least one action")
        self.name = name
        self.trigger = trigger
        self.actions = list(actions)
        self.conditions = list(conditions or [])
        self.enabled = bool(enabled)
        self.description = description
        self.max_retries = max(0, int(max_retries))
        self.timeout_seconds = float(timeout_seconds)
        self.cooldown_seconds = float(cooldown_seconds)
        self.max_depth = int(max_depth)
        self.dedup_fields = list(dedup_fields or [])
        self.retry_backoff_seconds = float(retry_backoff_seconds)

    @classmethod
    def from_dict(cls, data: dict) -> "WorkflowDefinition":
        trigger = data.get("trigger")
        # Accept both flat {"trigger": "x"} and nested {"trigger": {"event": "x"}}.
        if isinstance(trigger, dict):
            trigger = trigger.get("event")
        actions = data.get("actions") or []
        # Accept ["log_event"] or [{"action": "log_event"}].
        norm_actions = [a["action"] if isinstance(a, dict) else a for a in actions]
        return cls(
            name=data["name"],
            trigger=trigger,
            actions=norm_actions,
            conditions=data.get("conditions"),
            enabled=data.get("enabled", True),
            description=data.get("description", ""),
            max_retries=data.get("max_retries", 0),
            timeout_seconds=data.get("timeout_seconds", 30.0),
            cooldown_seconds=data.get("cooldown_seconds", 0.0),
            max_depth=data.get("max_depth", 5),
            dedup_fields=data.get("dedup_fields"),
            retry_backoff_seconds=data.get("retry_backoff_seconds", 0.5),
        )

    def dedup_key(self, event: Event) -> Optional[str]:
        if not self.dedup_fields:
            return None
        parts = [self.name]
        for field in self.dedup_fields:
            parts.append(f"{field}={event.payload.get(field)!r}")
        return "|".join(parts)

    def as_dict(self) -> dict:
        return {
            "name": self.name, "trigger": self.trigger, "actions": self.actions,
            "conditions": self.conditions, "enabled": self.enabled,
            "description": self.description, "max_retries": self.max_retries,
            "timeout_seconds": self.timeout_seconds,
            "cooldown_seconds": self.cooldown_seconds, "max_depth": self.max_depth,
            "dedup_fields": self.dedup_fields,
        }


# ---------------- Engine ----------------

class WorkflowEngine:
    def __init__(self, action_registry: ActionRegistry,
                 services: Optional[Services] = None,
                 db_path: Optional[str] = None):
        self.actions = action_registry
        self.services = services or Services()
        self.db_path = db_path
        self._workflows: Dict[str, WorkflowDefinition] = {}
        # dedup_key -> last successful run monotonic time (in-memory fast path)
        self._recent: Dict[str, float] = {}

    # ---- registration ----

    def register(self, definition: WorkflowDefinition, *, replace: bool = False) -> None:
        if definition.name in self._workflows and not replace:
            raise ValueError(f"workflow {definition.name!r} already registered")
        # Validate action names up front so a typo surfaces at load, not at fire.
        for action_name in definition.actions:
            if action_name not in self.actions:
                logger.warning(
                    "WORKFLOW %s references unknown action %r; it will no-op",
                    definition.name, action_name,
                )
        self._workflows[definition.name] = definition
        self._load_persisted_enabled(definition)

    def register_many(self, definitions) -> None:
        for definition in definitions:
            self.register(definition, replace=True)

    def get(self, name: str) -> Optional[WorkflowDefinition]:
        return self._workflows.get(name)

    def list(self) -> List[WorkflowDefinition]:
        return sorted(self._workflows.values(), key=lambda w: w.name)

    def workflows_for(self, event_type: str) -> List[WorkflowDefinition]:
        return [w for w in self._workflows.values()
                if w.trigger == event_type and w.enabled]

    # ---- enable / disable (persisted) ----

    def set_enabled(self, name: str, enabled: bool, actor: Optional[int] = None) -> bool:
        wf = self._workflows.get(name)
        if wf is None:
            return False
        wf.enabled = enabled
        self._persist_enabled(name, enabled, actor)
        return True

    def _load_persisted_enabled(self, definition: WorkflowDefinition) -> None:
        if not self.db_path:
            return
        try:
            conn = self._conn()
            row = conn.execute(
                "SELECT enabled FROM wf_workflow_state WHERE name=?",
                (definition.name,),
            ).fetchone()
            conn.close()
            if row is not None:
                definition.enabled = bool(row["enabled"])
        except sqlite3.Error:
            logger.debug("WORKFLOW | could not read persisted state for %s",
                         definition.name)

    def _persist_enabled(self, name: str, enabled: bool, actor: Optional[int]) -> None:
        if not self.db_path:
            return
        try:
            conn = self._conn()
            conn.execute(
                "INSERT INTO wf_workflow_state (name, enabled, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, "
                "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (name, 1 if enabled else 0, int(time.time()), actor),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error:
            logger.exception("WORKFLOW | could not persist state for %s", name)

    # ---- dispatch ----

    async def dispatch(self, event: Event) -> List[ExecutionRecord]:
        """Match and run every workflow for ``event``. Returns one
        ExecutionRecord per workflow considered (including SKIPPED ones), so a
        caller/test can see exactly what happened. Never raises: a workflow's
        failure is captured in its record, isolated from the others."""
        records: List[ExecutionRecord] = []
        matched = self.workflows_for(event.type)
        if not matched:
            return records

        for wf in matched:
            try:
                record = await self._run_workflow(wf, event)
            except Exception as exc:  # last-resort isolation
                logger.exception("WORKFLOW %s crashed on %s", wf.name, event.type)
                record = ExecutionRecord(
                    execution_id=uuid.uuid4().hex, workflow_name=wf.name,
                    event_type=event.type, correlation_id=event.correlation_id,
                    dedup_key=wf.dedup_key(event), state=WorkflowState.FAILED.value,
                    depth=event.depth, error=str(exc),
                )
                self._persist_execution(record)
            records.append(record)
        return records

    async def _run_workflow(self, wf: WorkflowDefinition, event: Event) -> ExecutionRecord:
        execution_id = uuid.uuid4().hex
        dedup_key = wf.dedup_key(event)
        record = ExecutionRecord(
            execution_id=execution_id, workflow_name=wf.name, event_type=event.type,
            correlation_id=event.correlation_id, dedup_key=dedup_key,
            state=WorkflowState.PENDING.value, depth=event.depth,
        )

        # ---- loop guard ----
        if event.depth > wf.max_depth:
            record.state = WorkflowState.SKIPPED.value
            record.error = f"max_depth {wf.max_depth} exceeded (depth={event.depth})"
            record.log.append(record.error)
            self._audit(wf, event, execution_id, "loop-guard",
                        f"skipped: {record.error}", severity="warning")
            self._persist_execution(record)
            return record

        # ---- conditions ----
        if not evaluate_all(wf.conditions, event.payload):
            record.state = WorkflowState.SKIPPED.value
            record.log.append("conditions not met")
            self._persist_execution(record)
            return record

        # ---- dedup / idempotency ----
        if dedup_key and wf.cooldown_seconds > 0:
            last = self._recent.get(dedup_key)
            now = time.monotonic()
            if last is not None and (now - last) < wf.cooldown_seconds:
                record.state = WorkflowState.SKIPPED.value
                record.log.append(
                    f"deduplicated within cooldown {wf.cooldown_seconds}s")
                self._audit(wf, event, execution_id, "dedup",
                            "skipped duplicate", severity="info")
                self._persist_execution(record)
                return record

        # ---- run ----
        record.state = WorkflowState.RUNNING.value
        record.started_at = int(time.time())
        self._audit(wf, event, execution_id, "started",
                    f"trigger={event.type}", severity="info")

        try:
            await asyncio.wait_for(
                self._execute_actions(wf, event, record),
                timeout=wf.timeout_seconds,
            )
            record.state = WorkflowState.SUCCESS.value
            if dedup_key:
                self._recent[dedup_key] = time.monotonic()
            self._audit(wf, event, execution_id, "completed", "ok", severity="info")
        except asyncio.TimeoutError:
            record.state = WorkflowState.TIMEOUT.value
            record.error = f"timed out after {wf.timeout_seconds}s"
            record.log.append(record.error)
            self._audit(wf, event, execution_id, "timeout", record.error,
                        severity="error")
        except Exception as exc:
            record.state = WorkflowState.FAILED.value
            record.error = str(exc)
            record.log.append(f"failed: {exc}")
            self._audit(wf, event, execution_id, "failed", str(exc), severity="error")

        record.finished_at = int(time.time())
        self._persist_execution(record)
        return record

    async def _execute_actions(self, wf: WorkflowDefinition, event: Event,
                               record: ExecutionRecord) -> None:
        emitted: List[Event] = []
        for action_name in wf.actions:
            action = self.actions.get(action_name)
            if action is None:
                record.log.append(f"action {action_name}: not registered (skipped)")
                continue
            result = await self._run_action_with_retry(wf, action, event, record)
            record.log.append(
                f"action {action_name}: "
                f"{'ok' if result.ok else 'FAILED'} {result.detail}")
            if not result.ok:
                raise RuntimeError(f"action {action_name} failed: {result.detail}")
            emitted.extend(result.emit)

        # Emit follow-up events AFTER all actions succeed, so a chain is only
        # extended by a fully successful run. Depth was already incremented by
        # Event.child(), which is what the loop guard reads.
        for child in emitted:
            self._log_step(record, "emit", f"-> {child.type} (depth={child.depth})")
            await self.dispatch(child)

    async def _run_action_with_retry(self, wf, action, event, record):
        context = {
            "event": event, "services": self.services,
            "execution_id": record.execution_id,
            "correlation_id": event.correlation_id, "depth": event.depth,
            "logger": logger,
        }
        attempt = 0
        last_result = None
        while attempt <= wf.max_retries:
            record.attempts += 1
            attempt += 1
            try:
                last_result = await action.execute(context)
            except Exception as exc:
                last_result = self._failure_result(action.name, str(exc))
            if last_result.ok:
                return last_result
            self._log_step(record, action.name,
                           f"attempt {attempt} failed: {last_result.detail}")
            if attempt <= wf.max_retries:
                await asyncio.sleep(wf.retry_backoff_seconds * attempt)
        return last_result

    @staticmethod
    def _failure_result(action_name, detail):
        from .models import ActionResult
        return ActionResult.failure(action_name, detail)

    # ---- persistence ----

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _log_step(self, record: ExecutionRecord, action: str, message: str) -> None:
        record.log.append(f"{action}: {message}")
        if not self.db_path:
            return
        try:
            conn = self._conn()
            conn.execute(
                "INSERT INTO wf_execution_log (execution_id, created_at, level, "
                "action, message) VALUES (?, ?, ?, ?, ?)",
                (record.execution_id, int(time.time()), "info", action, message),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error:
            logger.debug("WORKFLOW | could not write execution log step")

    def _persist_execution(self, record: ExecutionRecord) -> None:
        if not self.db_path:
            return
        try:
            conn = self._conn()
            conn.execute(
                "INSERT INTO wf_executions (execution_id, workflow_name, event_type, "
                "correlation_id, dedup_key, state, depth, attempts, created_at, "
                "started_at, finished_at, error, context_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(execution_id) DO UPDATE SET state=excluded.state, "
                "attempts=excluded.attempts, started_at=excluded.started_at, "
                "finished_at=excluded.finished_at, error=excluded.error",
                (record.execution_id, record.workflow_name, record.event_type,
                 record.correlation_id, record.dedup_key, record.state, record.depth,
                 record.attempts, record.created_at, record.started_at,
                 record.finished_at, record.error,
                 json.dumps({"log": record.log})[:8000]),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error:
            logger.exception("WORKFLOW | could not persist execution %s",
                             record.execution_id)

    def _audit(self, wf, event, execution_id, action, detail, severity="info") -> None:
        if not self.db_path:
            return
        try:
            conn = self._conn()
            conn.execute(
                "INSERT INTO wf_audit (created_at, workflow_name, event_type, "
                "execution_id, correlation_id, severity, actor, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (int(time.time()), wf.name, event.type, execution_id,
                 event.correlation_id, severity, "system", f"{action}: {detail}"),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error:
            logger.debug("WORKFLOW | could not write audit row")

    # ---- history for /workflow history ----

    def history(self, workflow_name: Optional[str] = None, limit: int = 20) -> List[dict]:
        if not self.db_path:
            return []
        try:
            conn = self._conn()
            if workflow_name:
                rows = conn.execute(
                    "SELECT * FROM wf_executions WHERE workflow_name=? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (workflow_name, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM wf_executions ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    def stats(self) -> dict:
        enabled = [w.name for w in self._workflows.values() if w.enabled]
        disabled = [w.name for w in self._workflows.values() if not w.enabled]
        by_state: Dict[str, int] = {}
        if self.db_path:
            try:
                conn = self._conn()
                for state, count in conn.execute(
                    "SELECT state, COUNT(*) FROM wf_executions GROUP BY state"
                ).fetchall():
                    by_state[state] = count
                conn.close()
            except sqlite3.Error:
                pass
        return {
            "total": len(self._workflows),
            "enabled": enabled,
            "disabled": disabled,
            "executions_by_state": by_state,
        }
