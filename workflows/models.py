"""
workflows/models.py — value objects shared across the workflow engine.

Kept deliberately dependency-free (stdlib + dataclasses only) so the engine
can be unit-tested without Telegram, the database, or any feature module.
"""

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------- Canonical trigger names ----------------
# The event vocabulary the engine understands. app.py emits these; a
# workflow's trigger matches one of them. Kept as plain strings so new
# triggers can be added without a code change to the engine, but the well
# known ones are named here for discoverability and validation.

class Trigger(str, Enum):
    MESSAGE_RECEIVED = "message.received"
    MESSAGE_DELETED = "message.deleted"
    DETECTION_TRIGGERED = "detection.triggered"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    EVIDENCE_CREATED = "evidence.created"
    MEMBER_JOINED = "member.joined"
    MEMBER_LEFT = "member.left"
    SYSTEM_ERROR = "system.error"


KNOWN_TRIGGERS = frozenset(t.value for t in Trigger)


# ---------------- Execution state machine ----------------

class WorkflowState(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"      # conditions/dedup/loop-guard declined to run it


TERMINAL_STATES = frozenset({
    WorkflowState.SUCCESS.value,
    WorkflowState.FAILED.value,
    WorkflowState.CANCELLED.value,
    WorkflowState.TIMEOUT.value,
    WorkflowState.SKIPPED.value,
})


# ---------------- Event ----------------

@dataclass
class Event:
    """Something that happened in the bot. ``type`` is one of the trigger
    strings; ``payload`` is a flat-ish dict the conditions read fields from.

    ``depth`` is the loop-guard counter: an event created as a side effect of
    a workflow action carries depth = parent_depth + 1, so a chain of
    incident.created -> update -> incident.updated -> ... cannot recurse
    forever. ``correlation_id`` ties an event and everything it triggers into
    one traceable chain.
    """
    type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    depth: int = 0
    source: str = "app"
    timestamp: float = field(default_factory=time.time)

    def child(self, type: str, payload: Optional[Dict[str, Any]] = None,
              source: str = "workflow") -> "Event":
        """Derive a follow-up event that inherits this one's correlation id
        and increments depth — the mechanism that makes loop detection work."""
        return Event(
            type=type,
            payload=payload or {},
            correlation_id=self.correlation_id,
            depth=self.depth + 1,
            source=source,
        )

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------- Action result ----------------

@dataclass
class ActionResult:
    ok: bool
    action: str
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    # Events an action wants the engine to emit after it succeeds (e.g.
    # create_incident emitting incident.created). The engine stamps depth.
    emit: List[Event] = field(default_factory=list)

    @classmethod
    def success(cls, action: str, detail: str = "", **data) -> "ActionResult":
        return cls(ok=True, action=action, detail=detail, data=data)

    @classmethod
    def failure(cls, action: str, detail: str = "", **data) -> "ActionResult":
        return cls(ok=False, action=action, detail=detail, data=data)


# ---------------- Execution record ----------------

@dataclass
class ExecutionRecord:
    execution_id: str
    workflow_name: str
    event_type: str
    correlation_id: str
    dedup_key: Optional[str]
    state: str
    depth: int
    attempts: int = 0
    created_at: int = field(default_factory=lambda: int(time.time()))
    started_at: Optional[int] = None
    finished_at: Optional[int] = None
    error: Optional[str] = None
    log: List[str] = field(default_factory=list)
