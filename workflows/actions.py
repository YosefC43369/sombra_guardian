"""
workflows/actions.py — the action interface, a registry, and safe built-ins.

An action is a named, async unit of work a workflow performs when its trigger
and conditions match. The interface is intentionally tiny:

    class WorkflowAction:
        name: str
        async def execute(self, context) -> ActionResult

``context`` is a dict the engine builds per run:
    {"event": Event, "services": Services, "execution_id": str,
     "correlation_id": str, "depth": int, "logger": logging.Logger}

Decoupling
----------
This module imports NO feature code (member_incident, detection, telegram).
Actions that need those talk to them through a ``Services`` container that
sg_platform fills in at boot. When a service is not wired up (unit tests, a
minimal deployment, or a degraded start), the action logs and returns a
stub-success result instead of raising — a missing side effect must never
crash the engine. This is the safe-stub rule the task calls for.
"""

import inspect
import logging
from typing import Any, Callable, Dict, Optional

from .models import ActionResult

logger = logging.getLogger("modbot.workflows.actions")


class Services:
    """A bag of optional callables the built-in actions use. sg_platform
    sets the ones a live bot supports; anything left None makes the matching
    action degrade to a logged stub.

    Callables (all optional):
      send_message(chat_id, text) -> Any
      send_admin_alert(chat_id, text) -> Any
      create_incident(chat_id, user_id, category, severity, reason, meta) -> dict
      update_incident(incident_id, status, actor, reason) -> dict
      create_evidence(chat_id, user_id, incident_id, kind, content, meta) -> dict
      run_detection(chat_id, user_id, text) -> Any
      generate_report(kind, params) -> Any
    """

    def __init__(self, **callables: Optional[Callable]):
        self._callables: Dict[str, Optional[Callable]] = dict(callables)

    def get(self, name: str) -> Optional[Callable]:
        return self._callables.get(name)

    def set(self, name: str, fn: Optional[Callable]) -> None:
        self._callables[name] = fn

    def has(self, name: str) -> bool:
        return callable(self._callables.get(name))


class WorkflowAction:
    """Base class for a workflow action. Subclasses set ``name`` and
    implement ``execute``."""

    name: str = ""

    async def execute(self, context: Dict[str, Any]) -> ActionResult:  # pragma: no cover
        raise NotImplementedError


class ActionRegistry:
    def __init__(self):
        self._actions: Dict[str, WorkflowAction] = {}

    def register(self, action: WorkflowAction, *, replace: bool = False) -> None:
        if not action.name:
            raise ValueError("action must define a non-empty name")
        if action.name in self._actions and not replace:
            raise ValueError(f"action {action.name!r} already registered")
        self._actions[action.name] = action

    def get(self, name: str) -> Optional[WorkflowAction]:
        return self._actions.get(name)

    def names(self):
        return sorted(self._actions)

    def __contains__(self, name: str) -> bool:
        return name in self._actions


# ---------------- Helpers ----------------

async def _call_service(context, service_name: str, *args, **kwargs):
    """Invoke a wired service if present, awaiting it when it is a coroutine
    (e.g. a Telegram ``bot.send_message``). Returns ``(available, result)``;
    a service that raises is surfaced to the caller as an exception, which the
    engine's retry/failure handling then captures."""
    services: Services = context["services"]
    fn = services.get(service_name)
    if not callable(fn):
        return False, None
    result = fn(*args, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    return True, result


# ---------------- Built-in actions ----------------

class LogEventAction(WorkflowAction):
    """Always-safe: records that the workflow saw this event. Used both as a
    useful default action and as the reference implementation."""
    name = "log_event"

    async def execute(self, context):
        event = context["event"]
        context["logger"].info(
            "WORKFLOW log_event | corr=%s type=%s payload_keys=%s",
            context["correlation_id"], event.type, sorted(event.payload.keys()),
        )
        return ActionResult.success(self.name, f"logged {event.type}")


class SendMessageAction(WorkflowAction):
    name = "send_message"

    async def execute(self, context):
        event = context["event"]
        chat_id = event.payload.get("chat_id")
        text = event.payload.get("message") or event.payload.get("reason") \
            or f"workflow: {event.type}"
        available, _ = await _call_service(context, "send_message", chat_id, text)
        if not available:
            context["logger"].info("WORKFLOW send_message (stub) | chat=%s: %s",
                                   chat_id, text)
            return ActionResult.success(self.name, "stub (no send_message service)")
        return ActionResult.success(self.name, "message sent")


class SendAdminAlertAction(WorkflowAction):
    name = "send_admin_alert"

    async def execute(self, context):
        event = context["event"]
        chat_id = event.payload.get("chat_id")
        reason = event.payload.get("reason") or event.type
        text = f"🚨 {event.type}: {reason}"
        available, _ = await _call_service(context, "send_admin_alert", chat_id, text)
        if not available:
            context["logger"].info("WORKFLOW send_admin_alert (stub) | chat=%s: %s",
                                   chat_id, text)
            return ActionResult.success(self.name, "stub (no send_admin_alert service)")
        return ActionResult.success(self.name, "admin alerted")


class CreateIncidentAction(WorkflowAction):
    name = "create_incident"

    async def execute(self, context):
        event = context["event"]
        p = event.payload
        available, result = await _call_service(
            context, "create_incident",
            p.get("chat_id"), p.get("user_id"),
            p.get("category", "OTHER_SECURITY_EVENT"),
            p.get("severity", "medium"), p.get("reason", ""), dict(p),
        )
        if not available:
            context["logger"].info("WORKFLOW create_incident (stub) | %s", p.get("reason"))
            return ActionResult.success(self.name, "stub (no create_incident service)")
        incident_id = None
        if isinstance(result, dict):
            incident_id = result.get("incident_id")
        emit = []
        if incident_id:
            emit.append(event.child("incident.created", {
                **p, "incident_id": incident_id,
            }))
        return ActionResult(ok=True, action=self.name,
                            detail=f"incident {incident_id}",
                            data={"incident_id": incident_id}, emit=emit)


class UpdateIncidentAction(WorkflowAction):
    name = "update_incident"

    async def execute(self, context):
        event = context["event"]
        p = event.payload
        available, result = await _call_service(
            context, "update_incident",
            p.get("incident_id"), p.get("status", "TRIAGED"),
            p.get("actor"), p.get("reason", ""),
        )
        if not available:
            context["logger"].info("WORKFLOW update_incident (stub) | id=%s",
                                   p.get("incident_id"))
            return ActionResult.success(self.name, "stub (no update_incident service)")
        emit = [event.child("incident.updated", dict(p))]
        return ActionResult(ok=True, action=self.name,
                            detail=f"incident {p.get('incident_id')} updated",
                            emit=emit)


class CreateEvidenceAction(WorkflowAction):
    name = "create_evidence"

    async def execute(self, context):
        event = context["event"]
        p = event.payload
        available, result = await _call_service(
            context, "create_evidence",
            p.get("chat_id"), p.get("user_id"), p.get("incident_id"),
            p.get("kind", "SYSTEM"), p.get("content"), dict(p),
        )
        if not available:
            context["logger"].info("WORKFLOW create_evidence (stub) | incident=%s",
                                   p.get("incident_id"))
            return ActionResult.success(self.name, "stub (no create_evidence service)")
        evidence_id = result.get("evidence_id") if isinstance(result, dict) else None
        emit = []
        if evidence_id:
            emit.append(event.child("evidence.created", {**p, "evidence_id": evidence_id}))
        return ActionResult(ok=True, action=self.name,
                            detail=f"evidence {evidence_id}",
                            data={"evidence_id": evidence_id}, emit=emit)


class RunDetectionAction(WorkflowAction):
    name = "run_detection"

    async def execute(self, context):
        event = context["event"]
        p = event.payload
        available, result = await _call_service(
            context, "run_detection",
            p.get("chat_id"), p.get("user_id"), p.get("text", ""),
        )
        if not available:
            return ActionResult.success(self.name, "stub (no run_detection service)")
        return ActionResult.success(self.name, "detection run",
                                    result=str(result)[:200])


class GenerateReportAction(WorkflowAction):
    name = "generate_report"

    async def execute(self, context):
        event = context["event"]
        p = event.payload
        available, result = await _call_service(
            context, "generate_report", p.get("report", event.type), dict(p),
        )
        if not available:
            context["logger"].info("WORKFLOW generate_report (stub) | %s", event.type)
            return ActionResult.success(self.name, "stub (no generate_report service)")
        return ActionResult.success(self.name, "report generated")


def build_default_registry() -> ActionRegistry:
    """A registry pre-loaded with every built-in action. Plugins add more
    via the plugin context; sg_platform wires the services."""
    registry = ActionRegistry()
    for action_cls in (
        LogEventAction, SendMessageAction, SendAdminAlertAction,
        CreateIncidentAction, UpdateIncidentAction, CreateEvidenceAction,
        RunDetectionAction, GenerateReportAction,
    ):
        registry.register(action_cls())
    return registry
