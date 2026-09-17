"""
workflows/ — the Workflow Automation Engine for Sombra Guardian.

Turns events already produced by the bot (detection hits, incidents,
evidence, member joins/leaves, system errors) into declarative, auditable
automations:

    Event -> Event Bus -> match trigger -> evaluate conditions
          -> run actions (retry/timeout, loop-guarded) -> execution log/audit

The package is deliberately free of Telegram and feature-module imports so it
can be unit-tested in isolation; actions reach the rest of the bot through an
injected :class:`Services` container that sg_platform fills in at boot.

Public surface
--------------
``Event`` / ``Trigger`` / ``WorkflowState``   event + state vocabulary
``EventBus``                                  publish/subscribe hub
``WorkflowEngine`` / ``WorkflowDefinition``   matching + safe execution
``WorkflowAction`` / ``ActionRegistry`` / ``Services`` / ``build_default_registry``
``load_dir`` / ``load_file``                  definition loading
"""

from .models import Event, Trigger, WorkflowState, ActionResult, ExecutionRecord, KNOWN_TRIGGERS
from .event_bus import EventBus
from .conditions import evaluate_condition, evaluate_all, safe_regex_search, ConditionError
from .actions import (
    WorkflowAction, ActionRegistry, Services, build_default_registry,
)
from .engine import WorkflowEngine, WorkflowDefinition
from .loader import load_dir, load_file

__all__ = [
    "Event", "Trigger", "WorkflowState", "ActionResult", "ExecutionRecord",
    "KNOWN_TRIGGERS", "EventBus",
    "evaluate_condition", "evaluate_all", "safe_regex_search", "ConditionError",
    "WorkflowAction", "ActionRegistry", "Services", "build_default_registry",
    "WorkflowEngine", "WorkflowDefinition", "load_dir", "load_file",
]
