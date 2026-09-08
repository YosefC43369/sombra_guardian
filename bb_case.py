"""
bb_case.py — Phase 7: Bug Bounty Case Management.

A Case is the *management* layer that sits on top of an existing
Finding. The Finding stays the single source of truth for the technical
data (target, title, severity, scope decision); a Case only answers
"who is handling this, how urgently, and where is it in our workflow".

Deliberate non-responsibilities (these belong to modules that already
own them, and this module must never grow them):
  - Scope / authorization decisions -> scope_policy.evaluate_target().
    This module never imports it. A Case is downstream metadata and can
    never widen, narrow, or bypass what a Program authorizes.
  - Finding technical data and the Finding state machine -> findings.py.
    Case status is a *separate* state machine that runs alongside the
    Finding's, never overwrites it, and never writes to bb_findings.
  - Audit logging -> security.write_audit_log(). No second audit system.
  - Database location -> security.DB_PATH. No second database.

Design constraints (matches security.py / scope_policy.py / findings.py):
  - Standard library only.
  - CREATE TABLE IF NOT EXISTS only; idempotent init; never a
    destructive migration.
  - Every query parameterized. No SQL is ever built from user input.
  - Notes and timeline messages are inert data: stored, length-capped,
    and rendered as text. Never evaluated, never imported, never fed to
    a subprocess, and never consulted by any permission check.
"""

import time
import sqlite3
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from security import DB_PATH, write_audit_log
from findings import get_finding
from scope_policy import get_program

logger = logging.getLogger(__name__)


# ---------------- Enums / Constants ----------------

class CasePriority(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    URGENT = "URGENT"


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGE = "TRIAGE"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING = "WAITING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    CANCELLED = "CANCELLED"


class CaseEvent(str, Enum):
    CASE_CREATED = "CASE_CREATED"
    ASSIGNED = "ASSIGNED"
    UNASSIGNED = "UNASSIGNED"
    PRIORITY_CHANGED = "PRIORITY_CHANGED"
    STATUS_CHANGED = "STATUS_CHANGED"
    NOTE_ADDED = "NOTE_ADDED"


VALID_PRIORITIES = {p.value for p in CasePriority}
VALID_CASE_STATUSES = {s.value for s in CaseStatus}
VALID_CASE_EVENTS = {e.value for e in CaseEvent}

DEFAULT_PRIORITY = CasePriority.NORMAL.value

# Terminal states. A terminal Case is never reopened: there is no
# transition out of either, and no admin bypass anywhere in this module
# that could add one at runtime.
TERMINAL_CASE_STATUSES = frozenset({CaseStatus.CLOSED.value, CaseStatus.CANCELLED.value})

# A Case that is not finished yet still occupies its Finding. This is
# the Python-side half of the "one active Case per Finding" rule; the
# other half is the partial UNIQUE index created in bb_case_db_init().
ACTIVE_CASE_STATUSES = tuple(sorted(VALID_CASE_STATUSES - TERMINAL_CASE_STATUSES))

# Explicit management workflow. Chosen to run *alongside* findings.py's
# state machine (OPEN/TRIAGED/CONFIRMED -> RESOLVED, with REJECTED and
# DUPLICATE terminal) without contradicting it: a Case never asserts
# anything about whether a vulnerability is real, only about whether the
# team has finished handling the paperwork. That is why RESOLVED here
# does not require the Finding to be RESOLVED, and why CANCELLED exists
# (the Case is dropped, e.g. the Finding turned out to be a DUPLICATE,
# while the Finding keeps its own status).
_ALLOWED_CASE_TRANSITIONS: Dict[str, set] = {
    CaseStatus.OPEN.value: {
        CaseStatus.TRIAGE.value,
        CaseStatus.CANCELLED.value,
    },
    CaseStatus.TRIAGE.value: {
        CaseStatus.ASSIGNED.value,
        CaseStatus.WAITING.value,
        CaseStatus.CANCELLED.value,
    },
    CaseStatus.ASSIGNED.value: {
        CaseStatus.IN_PROGRESS.value,
        CaseStatus.WAITING.value,
        CaseStatus.TRIAGE.value,
        CaseStatus.CANCELLED.value,
    },
    CaseStatus.IN_PROGRESS.value: {
        CaseStatus.WAITING.value,
        CaseStatus.RESOLVED.value,
        CaseStatus.TRIAGE.value,
        CaseStatus.CANCELLED.value,
    },
    CaseStatus.WAITING.value: {
        CaseStatus.ASSIGNED.value,
        CaseStatus.IN_PROGRESS.value,
        CaseStatus.TRIAGE.value,
        CaseStatus.CANCELLED.value,
    },
    CaseStatus.RESOLVED.value: {
        CaseStatus.CLOSED.value,
    },
    CaseStatus.CLOSED.value: set(),
    CaseStatus.CANCELLED.value: set(),
}

# Entering these requires an assignee to already be set, so
# "status == ASSIGNED implies assignee IS NOT NULL" holds at all times.
_STATUSES_REQUIRING_ASSIGNEE = frozenset({
    CaseStatus.ASSIGNED.value,
    CaseStatus.IN_PROGRESS.value,
})

MAX_NOTE_LEN = 2000
MAX_STATUS_MESSAGE_LEN = 2000
MAX_LIST_LIMIT = 100
DEFAULT_LIST_LIMIT = 20
DEFAULT_TIMELINE_LIMIT = 30


@dataclass
class CaseResult:
    ok: bool
    case_id: Optional[int] = None
    reason: str = ""
    detail: str = ""


def _cr(ok: bool, reason: str, case_id: Optional[int] = None, detail: str = "") -> CaseResult:
    return CaseResult(ok=ok, case_id=case_id, reason=reason, detail=detail)


# ---------------- Validation helpers ----------------

def _valid_id(value: Any) -> bool:
    """True only for a real positive integer row id. `bool` is rejected
    explicitly: isinstance(True, int) is True in Python, so without this
    a stray True would silently be accepted as id 1."""
    if isinstance(value, bool):
        return False
    return isinstance(value, int) and value > 0


def _valid_user_id(value: Any) -> bool:
    """Telegram user ids are positive integers. Same bool guard as above.
    This module never invents its own identity space -- the id stored in
    `assignee` is the same `update.effective_user.id` that findings.py
    stores in `created_by`."""
    if isinstance(value, bool):
        return False
    return isinstance(value, int) and value > 0


def _clean_text(value: Optional[str], max_len: int) -> Optional[str]:
    """Returns trimmed text, or None if it is empty/oversized/contains a
    NUL byte. Text is only ever stored and displayed -- this function
    exists to bound it, not to make it 'safe to execute', because it is
    never executed."""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if "\x00" in text:
        return None
    if len(text) > max_len:
        return None
    return text


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def bb_case_db_init() -> None:
    """Create Phase 7 tables only. Reuses security.py's DB_PATH and
    audit_log table; never touches bb_programs / bb_authorizations /
    bb_scope_rules / bb_findings / bb_evidence or any other module's
    tables. Idempotent: safe to call on every process start, on a fresh
    database or on one that already holds Cases. Nothing here drops,
    renames, or rewrites an existing table or row."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_cases (
        case_id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'OPEN',
        priority TEXT NOT NULL DEFAULT 'NORMAL',
        assignee INTEGER,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        closed_at INTEGER,
        FOREIGN KEY (finding_id) REFERENCES bb_findings(finding_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_cases_finding ON bb_cases (finding_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_cases_status ON bb_cases (status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_cases_assignee ON bb_cases (assignee)")

    # Database-level guarantee for "at most one *active* Case per
    # Finding". A partial UNIQUE index lets a Finding be re-opened as a
    # brand new Case after the previous one reached CLOSED/CANCELLED,
    # while making a second concurrent active Case impossible even if
    # two callers race past the Python-side check below.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bb_cases_one_active_per_finding "
        "ON bb_cases (finding_id) WHERE status NOT IN ('CLOSED', 'CANCELLED')"
    )

    conn.execute("""CREATE TABLE IF NOT EXISTS bb_case_timeline (
        timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER NOT NULL,
        actor INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        message TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (case_id) REFERENCES bb_cases(case_id)
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bb_case_timeline_case "
        "ON bb_case_timeline (case_id, timeline_id)"
    )
    conn.commit()
    conn.close()
    logger.info("BB CASE DATABASE: OK")


# ---------------- Internal helpers ----------------

def _chat_id_for_case(case: Dict) -> int:
    """Resolves the chat a Case belongs to by walking Case -> Finding ->
    Program, exactly as findings.py does. The chat is never stored on the
    Case row, so a Program moving chats can't leave a stale copy behind."""
    finding = get_finding(case["finding_id"])
    if not finding:
        return 0
    program = get_program(finding["program_id"])
    return program["chat_id"] if program else 0


def _append_timeline(conn, case_id: int, actor: int, event_type: str,
                     message: Optional[str], now: int) -> None:
    """Appends one timeline row on the caller's open connection, so the
    entry lands inside the same transaction as the state change it
    describes. Never commits -- that stays the caller's decision."""
    conn.execute(
        "INSERT INTO bb_case_timeline (case_id, actor, event_type, message, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (case_id, actor, event_type, message, now),
    )


def _row_to_dict(row) -> Optional[Dict]:
    return dict(row) if row else None


# ---------------- Case: creation & reads ----------------

def create_case(finding_id: int, created_by: int,
                priority: str = DEFAULT_PRIORITY,
                note: str = "") -> CaseResult:
    """Opens a management Case for an existing Finding.

    The Finding must already exist -- which means it already passed
    scope_policy.evaluate_target() at creation time. This function does
    not re-run, relax, or second-guess that decision; it also cannot
    create a Case for a target that was never authorized, because there
    is no Finding for such a target in the first place.

    Copies nothing from the Finding. Title, target, severity and scope
    stay in bb_findings and are read live by get_case_summary().
    """
    if not _valid_id(finding_id):
        return _cr(False, "INVALID_FINDING_ID", detail=f"finding_id={finding_id!r}")
    if not _valid_user_id(created_by):
        return _cr(False, "INVALID_ACTOR", detail=f"created_by={created_by!r}")
    if priority not in VALID_PRIORITIES:
        return _cr(False, "INVALID_PRIORITY", detail=f"priority={priority!r}")

    opening_note = None
    if note:
        opening_note = _clean_text(note, MAX_NOTE_LEN)
        if opening_note is None:
            return _cr(False, "INVALID_NOTE", detail=f"max={MAX_NOTE_LEN}")

    finding = get_finding(finding_id)
    if not finding:
        return _cr(False, "FINDING_NOT_FOUND", detail=f"finding_id={finding_id}")

    now = int(time.time())
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT case_id FROM bb_cases WHERE finding_id=? AND status NOT IN (?, ?)",
            (finding_id, CaseStatus.CLOSED.value, CaseStatus.CANCELLED.value),
        ).fetchone()
        if existing:
            conn.rollback()
            return _cr(False, "ACTIVE_CASE_EXISTS", case_id=existing["case_id"],
                       detail=f"case_id={existing['case_id']} is still active for this finding")

        cur = conn.execute(
            "INSERT INTO bb_cases (finding_id, status, priority, assignee, created_by, "
            "created_at, updated_at) VALUES (?, ?, ?, NULL, ?, ?, ?)",
            (finding_id, CaseStatus.OPEN.value, priority, created_by, now, now),
        )
        case_id = cur.lastrowid
        _append_timeline(conn, case_id, created_by, CaseEvent.CASE_CREATED.value,
                         opening_note, now)
        conn.commit()
    except sqlite3.IntegrityError:
        # The partial UNIQUE index fired: another caller won the race
        # between our SELECT and our INSERT. Fail closed, never retry
        # into a second active Case.
        conn.rollback()
        conn.close()
        logger.info("BB CASE CREATE RACE LOST | finding_id=%s", finding_id)
        return _cr(False, "ACTIVE_CASE_EXISTS", detail="another active case was created concurrently")
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        logger.exception("BB CASE CREATE ERROR | finding_id=%s", finding_id)
        return _cr(False, "DATABASE_ERROR")
    conn.close()

    program = get_program(finding["program_id"])
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, created_by, actor="user", action="BB_CASE_CREATED",
                    detail=f"case_id={case_id} finding_id={finding_id} priority={priority}")
    logger.info("BB CASE CREATED | case_id=%s finding_id=%s", case_id, finding_id)
    return _cr(True, "OK", case_id=case_id)


def get_case(case_id: int) -> Optional[Dict]:
    if not _valid_id(case_id):
        return None
    conn = _conn()
    row = conn.execute("SELECT * FROM bb_cases WHERE case_id=?", (case_id,)).fetchone()
    conn.close()
    return _row_to_dict(row)


def get_case_by_finding(finding_id: int) -> Optional[Dict]:
    """The current *active* Case for a Finding, or None. Terminal Cases
    are intentionally excluded -- a CLOSED Case is history, not the case
    someone is looking for when they ask "what's happening with this"."""
    if not _valid_id(finding_id):
        return None
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM bb_cases WHERE finding_id=? AND status NOT IN (?, ?) "
        "ORDER BY case_id DESC LIMIT 1",
        (finding_id, CaseStatus.CLOSED.value, CaseStatus.CANCELLED.value),
    ).fetchone()
    conn.close()
    return _row_to_dict(row)


def list_cases(program_id: Optional[int] = None, status: Optional[str] = None,
               priority: Optional[str] = None, assignee: Optional[int] = None,
               limit: int = DEFAULT_LIST_LIMIT, offset: int = 0) -> List[Dict]:
    """Filtered Case listing. Every filter is a fixed, hard-coded SQL
    fragment chosen by a whitelist check -- user input only ever reaches
    the database as a bound parameter, never as SQL text. An invalid
    status/priority yields an empty list rather than being ignored, so a
    typo can never silently widen the result set.

    program_id is resolved through a JOIN on bb_findings instead of being
    denormalized onto bb_cases: the Finding stays the single source of
    truth for which Program a Case belongs to.
    """
    clauses = []
    params: List[Any] = []

    if program_id is not None:
        if not _valid_id(program_id):
            return []
        clauses.append("f.program_id = ?")
        params.append(program_id)

    if status is not None:
        if status not in VALID_CASE_STATUSES:
            return []
        clauses.append("c.status = ?")
        params.append(status)

    if priority is not None:
        if priority not in VALID_PRIORITIES:
            return []
        clauses.append("c.priority = ?")
        params.append(priority)

    if assignee is not None:
        if not _valid_user_id(assignee):
            return []
        clauses.append("c.assignee = ?")
        params.append(assignee)

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        limit = DEFAULT_LIST_LIMIT
    limit = min(limit, MAX_LIST_LIMIT)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        offset = 0

    sql = (
        "SELECT c.*, f.program_id AS program_id, f.severity AS severity, "
        "f.title AS finding_title, f.status AS finding_status "
        "FROM bb_cases c JOIN bb_findings f ON f.finding_id = c.finding_id"
    )
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY c.case_id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = _conn()
    rows = conn.execute(sql, tuple(params)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Case: assignment ----------------

def assign_case(case_id: int, assignee_user_id: int, actor_user_id: int) -> CaseResult:
    """Assigns (or reassigns) a Case to a handler. Terminal Cases reject.

    Assignment is management metadata only: it grants the assignee no
    authorization over any target, and no ability to change scope. Who
    is *allowed* to call this is enforced one layer up, in app.py's
    existing admin check -- deliberately the same gate that already
    guards /bbfinding status.
    """
    if not _valid_user_id(assignee_user_id):
        return _cr(False, "INVALID_ASSIGNEE", detail=f"assignee={assignee_user_id!r}")
    if not _valid_user_id(actor_user_id):
        return _cr(False, "INVALID_ACTOR", detail=f"actor={actor_user_id!r}")

    case = get_case(case_id)
    if not case:
        return _cr(False, "CASE_NOT_FOUND", detail=f"case_id={case_id!r}")
    if case["status"] in TERMINAL_CASE_STATUSES:
        return _cr(False, "CASE_TERMINAL", case_id=case_id, detail=f"status={case['status']}")
    if case["assignee"] == assignee_user_id:
        return _cr(False, "ALREADY_ASSIGNED", case_id=case_id,
                   detail=f"already assigned to {assignee_user_id}")

    previous = case["assignee"]
    now = int(time.time())
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        # Conditional UPDATE: if a concurrent call changed the assignee
        # or the status since our read, this matches zero rows and we
        # abort instead of silently clobbering the other writer.
        cur = conn.execute(
            "UPDATE bb_cases SET assignee=?, updated_at=? WHERE case_id=? AND status=? "
            "AND (assignee IS ? OR assignee = ?)",
            (assignee_user_id, now, case_id, case["status"], previous, previous),
        )
        if cur.rowcount != 1:
            conn.rollback()
            conn.close()
            return _cr(False, "CONCURRENT_MODIFICATION", case_id=case_id)
        message = f"assignee {previous if previous is not None else '-'} -> {assignee_user_id}"
        _append_timeline(conn, case_id, actor_user_id, CaseEvent.ASSIGNED.value, message, now)
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        logger.exception("BB CASE ASSIGN ERROR | case_id=%s", case_id)
        return _cr(False, "DATABASE_ERROR", case_id=case_id)
    conn.close()

    write_audit_log(_chat_id_for_case(case), actor_user_id, actor="user",
                    action="BB_CASE_ASSIGNED",
                    detail=f"case_id={case_id} assignee={assignee_user_id} previous={previous}")
    logger.info("BB CASE ASSIGNED | case_id=%s assignee=%s", case_id, assignee_user_id)
    return _cr(True, "OK", case_id=case_id)


def unassign_case(case_id: int, actor_user_id: int) -> CaseResult:
    """Clears the assignee.

    If the Case is currently in a status that requires an assignee
    (ASSIGNED / IN_PROGRESS), it is demoted to TRIAGE in the *same*
    transaction. That keeps the invariant "these statuses always have an
    assignee" true at every observable moment, and both the unassignment
    and the demotion are recorded on the timeline and in the audit log --
    nothing happens silently.
    """
    if not _valid_user_id(actor_user_id):
        return _cr(False, "INVALID_ACTOR", detail=f"actor={actor_user_id!r}")

    case = get_case(case_id)
    if not case:
        return _cr(False, "CASE_NOT_FOUND", detail=f"case_id={case_id!r}")
    if case["status"] in TERMINAL_CASE_STATUSES:
        return _cr(False, "CASE_TERMINAL", case_id=case_id, detail=f"status={case['status']}")
    if case["assignee"] is None:
        return _cr(False, "NOT_ASSIGNED", case_id=case_id)

    previous = case["assignee"]
    current_status = case["status"]
    demote = current_status in _STATUSES_REQUIRING_ASSIGNEE
    new_status = CaseStatus.TRIAGE.value if demote else current_status

    now = int(time.time())
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE bb_cases SET assignee=NULL, status=?, updated_at=? "
            "WHERE case_id=? AND status=? AND assignee=?",
            (new_status, now, case_id, current_status, previous),
        )
        if cur.rowcount != 1:
            conn.rollback()
            conn.close()
            return _cr(False, "CONCURRENT_MODIFICATION", case_id=case_id)
        _append_timeline(conn, case_id, actor_user_id, CaseEvent.UNASSIGNED.value,
                         f"assignee {previous} -> -", now)
        if demote:
            _append_timeline(conn, case_id, actor_user_id, CaseEvent.STATUS_CHANGED.value,
                             f"{current_status} -> {new_status} (unassigned)", now)
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        logger.exception("BB CASE UNASSIGN ERROR | case_id=%s", case_id)
        return _cr(False, "DATABASE_ERROR", case_id=case_id)
    conn.close()

    chat_id = _chat_id_for_case(case)
    write_audit_log(chat_id, actor_user_id, actor="user", action="BB_CASE_UNASSIGNED",
                    detail=f"case_id={case_id} previous={previous}")
    if demote:
        write_audit_log(chat_id, actor_user_id, actor="system", action="BB_CASE_STATUS_CHANGED",
                        detail=f"case_id={case_id} {current_status} -> {new_status} (unassigned)")
    logger.info("BB CASE UNASSIGNED | case_id=%s previous=%s demoted=%s",
                case_id, previous, demote)
    return _cr(True, "OK", case_id=case_id)


# ---------------- Case: priority ----------------

def set_case_priority(case_id: int, priority: str, actor_user_id: int) -> CaseResult:
    """Sets management urgency. Completely independent of the Finding's
    technical `severity`, which this function never reads and never
    writes: a CRITICAL Finding can sit at LOW priority (already mitigated
    elsewhere) and an INFO Finding can be URGENT (customer escalation).
    History is preserved through the timeline and the audit log, not by
    mutating the Finding."""
    if priority not in VALID_PRIORITIES:
        return _cr(False, "INVALID_PRIORITY", detail=f"priority={priority!r}")
    if not _valid_user_id(actor_user_id):
        return _cr(False, "INVALID_ACTOR", detail=f"actor={actor_user_id!r}")

    case = get_case(case_id)
    if not case:
        return _cr(False, "CASE_NOT_FOUND", detail=f"case_id={case_id!r}")
    if case["status"] in TERMINAL_CASE_STATUSES:
        return _cr(False, "CASE_TERMINAL", case_id=case_id, detail=f"status={case['status']}")

    previous = case["priority"]
    if previous == priority:
        return _cr(False, "PRIORITY_UNCHANGED", case_id=case_id, detail=f"priority={priority}")

    now = int(time.time())
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE bb_cases SET priority=?, updated_at=? WHERE case_id=? AND priority=? "
            "AND status NOT IN (?, ?)",
            (priority, now, case_id, previous,
             CaseStatus.CLOSED.value, CaseStatus.CANCELLED.value),
        )
        if cur.rowcount != 1:
            conn.rollback()
            conn.close()
            return _cr(False, "CONCURRENT_MODIFICATION", case_id=case_id)
        _append_timeline(conn, case_id, actor_user_id, CaseEvent.PRIORITY_CHANGED.value,
                         f"{previous} -> {priority}", now)
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        logger.exception("BB CASE PRIORITY ERROR | case_id=%s", case_id)
        return _cr(False, "DATABASE_ERROR", case_id=case_id)
    conn.close()

    write_audit_log(_chat_id_for_case(case), actor_user_id, actor="user",
                    action="BB_CASE_PRIORITY_CHANGED",
                    detail=f"case_id={case_id} {previous} -> {priority}")
    logger.info("BB CASE PRIORITY | case_id=%s %s -> %s", case_id, previous, priority)
    return _cr(True, "OK", case_id=case_id)


# ---------------- Case: workflow status ----------------

def update_case_status(case_id: int, new_status: str, actor_user_id: int,
                       message: str = "") -> CaseResult:
    """Deterministic Case state-machine transition.

    Rejects unknown status strings, rejects any transition not listed in
    _ALLOWED_CASE_TRANSITIONS, and rejects entering ASSIGNED/IN_PROGRESS
    without an assignee. Terminal states have an empty transition set, so
    a CLOSED or CANCELLED Case can never be reopened -- there is no
    parameter, flag, or privilege level that skips this check, because
    the function takes no privilege input at all.

    This never touches bb_findings: the Finding's own status is moved
    only through findings.update_finding_status().
    """
    if new_status not in VALID_CASE_STATUSES:
        return _cr(False, "INVALID_STATUS", detail=f"status={new_status!r}")
    if not _valid_user_id(actor_user_id):
        return _cr(False, "INVALID_ACTOR", detail=f"actor={actor_user_id!r}")

    note = None
    if message:
        note = _clean_text(message, MAX_STATUS_MESSAGE_LEN)
        if note is None:
            return _cr(False, "INVALID_MESSAGE", detail=f"max={MAX_STATUS_MESSAGE_LEN}")

    case = get_case(case_id)
    if not case:
        return _cr(False, "CASE_NOT_FOUND", detail=f"case_id={case_id!r}")

    current = case["status"]
    if new_status not in _ALLOWED_CASE_TRANSITIONS.get(current, set()):
        return _cr(False, "INVALID_TRANSITION", case_id=case_id,
                   detail=f"{current} -> {new_status} not allowed")
    if new_status in _STATUSES_REQUIRING_ASSIGNEE and case["assignee"] is None:
        return _cr(False, "ASSIGNEE_REQUIRED", case_id=case_id,
                   detail=f"{new_status} requires an assignee")

    now = int(time.time())
    closed_at = now if new_status in TERMINAL_CASE_STATUSES else case["closed_at"]
    detail_text = f"{current} -> {new_status}"

    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "UPDATE bb_cases SET status=?, closed_at=?, updated_at=? "
            "WHERE case_id=? AND status=?",
            (new_status, closed_at, now, case_id, current),
        )
        if cur.rowcount != 1:
            conn.rollback()
            conn.close()
            return _cr(False, "CONCURRENT_MODIFICATION", case_id=case_id)
        timeline_message = f"{detail_text}: {note}" if note else detail_text
        _append_timeline(conn, case_id, actor_user_id, CaseEvent.STATUS_CHANGED.value,
                         timeline_message, now)
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        logger.exception("BB CASE STATUS ERROR | case_id=%s", case_id)
        return _cr(False, "DATABASE_ERROR", case_id=case_id)
    conn.close()

    action = ("BB_CASE_CLOSED" if new_status == CaseStatus.CLOSED.value
              else "BB_CASE_STATUS_CHANGED")
    write_audit_log(_chat_id_for_case(case), actor_user_id, actor="user",
                    action=action, detail=f"case_id={case_id} {detail_text}")
    logger.info("BB CASE STATUS | case_id=%s %s", case_id, detail_text)
    return _cr(True, "OK", case_id=case_id)


# ---------------- Case: notes & timeline ----------------

def add_case_note(case_id: int, actor_user_id: int, message: str) -> CaseResult:
    """Appends a free-text management note.

    The note is stored verbatim as a bound parameter and read back as
    text. It is never parsed, evaluated, imported, executed, passed to a
    subprocess, or consulted by any scope/authorization/permission
    decision anywhere in this codebase. Only its length and encoding are
    constrained.
    """
    if not _valid_user_id(actor_user_id):
        return _cr(False, "INVALID_ACTOR", detail=f"actor={actor_user_id!r}")

    note = _clean_text(message, MAX_NOTE_LEN)
    if note is None:
        return _cr(False, "INVALID_NOTE", detail=f"note must be 1..{MAX_NOTE_LEN} chars")

    case = get_case(case_id)
    if not case:
        return _cr(False, "CASE_NOT_FOUND", detail=f"case_id={case_id!r}")
    if case["status"] in TERMINAL_CASE_STATUSES:
        return _cr(False, "CASE_TERMINAL", case_id=case_id, detail=f"status={case['status']}")

    now = int(time.time())
    conn = _conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _append_timeline(conn, case_id, actor_user_id, CaseEvent.NOTE_ADDED.value, note, now)
        conn.execute("UPDATE bb_cases SET updated_at=? WHERE case_id=?", (now, case_id))
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        logger.exception("BB CASE NOTE ERROR | case_id=%s", case_id)
        return _cr(False, "DATABASE_ERROR", case_id=case_id)
    conn.close()

    write_audit_log(_chat_id_for_case(case), actor_user_id, actor="user",
                    action="BB_CASE_NOTE_ADDED", detail=f"case_id={case_id} len={len(note)}")
    logger.info("BB CASE NOTE | case_id=%s actor=%s", case_id, actor_user_id)
    return _cr(True, "OK", case_id=case_id)


def list_timeline(case_id: int, limit: int = DEFAULT_TIMELINE_LIMIT,
                  offset: int = 0) -> List[Dict]:
    """Timeline entries oldest-first, so the list reads as a history.
    timeline_id is the ordering key rather than created_at: several
    events can share a second (see unassign_case's paired entries) and
    the autoincrement id preserves the order they actually happened in."""
    if not _valid_id(case_id):
        return []
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        limit = DEFAULT_TIMELINE_LIMIT
    limit = min(limit, MAX_LIST_LIMIT)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        offset = 0

    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_case_timeline WHERE case_id=? "
        "ORDER BY timeline_id ASC LIMIT ? OFFSET ?",
        (case_id, limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Case: summary ----------------

def get_case_summary(case_id: int) -> Optional[Dict]:
    """Structured Case summary, joining live Finding and Program data
    rather than a copy taken at Case-creation time.

    Deliberately narrow: it exposes only the management fields plus the
    Finding/Program identifiers a handler needs. No authorization rows,
    no scope rules, no evidence bytes, no credentials, and nothing from
    any unrelated table.
    """
    case = get_case(case_id)
    if not case:
        return None

    finding = get_finding(case["finding_id"])
    program = get_program(finding["program_id"]) if finding else None

    return {
        "case_id": case["case_id"],
        "finding_id": case["finding_id"],
        "program_id": finding["program_id"] if finding else None,
        "program_name": program["name"] if program else None,
        "finding_title": finding["title"] if finding else None,
        "finding_status": finding["status"] if finding else None,
        "severity": finding["severity"] if finding else None,
        "case_status": case["status"],
        "priority": case["priority"],
        "assignee": case["assignee"],
        "created_by": case["created_by"],
        "created_at": case["created_at"],
        "updated_at": case["updated_at"],
        "closed_at": case["closed_at"],
        "timeline_count": len(list_timeline(case_id, limit=MAX_LIST_LIMIT)),
    }


# ---------------- Presentation (pure functions over dicts) ----------------

def format_case_summary(data: Optional[Dict]) -> str:
    """Same split as bb_report.py: data-gathering and rendering live in
    this module, but rendering is a pure function of a plain dict and
    touches no database."""
    if not data:
        return "❌ ไม่พบ Case นี้"
    assignee = data["assignee"] if data["assignee"] is not None else "-"
    lines = [
        f"Case #{data['case_id']} [{data['case_status']}]",
        f"Finding: #{data['finding_id']} [{data['finding_status'] or '-'}]",
        f"Program: {data['program_name'] or '-'} (#{data['program_id'] if data['program_id'] else '-'})",
        f"หัวข้อ: {data['finding_title'] or '-'}",
        f"Severity (Finding): {data['severity'] or '-'}",
        f"Priority (Case): {data['priority']}",
        f"ผู้รับผิดชอบ: {assignee}",
        f"สร้างเมื่อ: {data['created_at']}",
        f"อัปเดตล่าสุด: {data['updated_at']}",
        f"Timeline: {data['timeline_count']} รายการ",
    ]
    if data["closed_at"]:
        lines.append(f"ปิดเมื่อ: {data['closed_at']}")
    return "\n".join(lines)


def format_case_list(rows: List[Dict]) -> str:
    if not rows:
        return "ไม่พบ Case ที่ตรงกับเงื่อนไข"
    lines = []
    for r in rows:
        assignee = r["assignee"] if r["assignee"] is not None else "-"
        lines.append(
            f"#{r['case_id']} [{r['status']}] P={r['priority']} "
            f"Finding #{r['finding_id']} ({r.get('severity', '-')}) "
            f"ผู้รับผิดชอบ: {assignee}"
        )
    return "Cases:\n" + "\n".join(lines)


def format_timeline(entries: List[Dict]) -> str:
    if not entries:
        return "ยังไม่มี timeline สำหรับ Case นี้"
    lines = []
    for e in entries:
        message = e["message"] or "-"
        lines.append(f"[{e['created_at']}] {e['event_type']} โดย {e['actor']}: {message}")
    return "Timeline:\n" + "\n".join(lines)