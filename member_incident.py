"""
member_incident.py — Phase 9: Incidents, Evidence Vault, Integrity & Custody

Answers the accountability half of the administrator's question:
"what happened, what evidence exists, is it intact, and what did we do
about it afterwards?"

Responsibilities (and only these):
  - Incident Engine        (structured incidents + lifecycle + notes)
  - Evidence Vault         (snapshots that survive later username changes)
  - Evidence Integrity     (SHA-256 over a canonical record, tamper check)
  - Chain of Custody       (append-only handling trail)
  - Admin Action Audit     (who did what to whom, only when observed)
  - Case linking           (an incident may reference one bb_case)

Deliberate non-responsibilities:
  - Identity registry, identity history, activity timeline, risk scoring
    and pattern analysis -> member_intel.py, which this module imports
    (never the reverse).
  - Telegram I/O and moderation decisions -> app.py. This module never
    imports telegram, never deletes/warns/mutes/bans, and never decides
    whether an action is permitted.
  - The global audit_log table -> security.write_audit_log(). The
    mi_admin_actions table here is a moderation-specific index, written
    ALONGSIDE that audit log, not instead of it.
  - Bug-bounty findings, programs, scope and their authorization
    decisions -> findings.py / bb_case.py / scope_policy.py. An incident
    may carry a bb_case reference (link_case) but can never create,
    widen, or bypass a bug-bounty authorization.
  - Report rendering / export -> member_report.py.

On what a hash does and does not prove: the integrity hash here proves
only that a stored evidence record is byte-identical to what was recorded
at capture time. It does NOT prove who created the content, that the
content is authentic, that the account named in it is a particular
person, or that any offence occurred. verify_evidence() reports MATCH or
MISMATCH about bytes, and nothing more.

On incidents and guilt: an incident is an administrative record that
something was flagged. Its existence is never a determination that the
account holder did anything wrong; that is what the UNDER_REVIEW ->
CONFIRMED / DISMISSED lifecycle is for, and CONFIRMED means "an
administrator agreed with the flag", not "a crime was committed".

Design constraints (matches findings.py / bb_case.py):
  - Standard library only. No network/API calls, no LLM calls, no
    background threads.
  - CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS only.
    Idempotent init; never a destructive migration.
  - Every query parameterized. No SQL is ever built from user input.
  - Message text, notes and filenames are inert data: stored, length-
    capped, rendered as text. Never evaluated, never imported, never
    passed to a subprocess, and never consulted by a permission check.
  - Chain-of-custody rows are append-only: this module contains no
    UPDATE or DELETE statement against mi_custody at all.
"""

import json
import time
import sqlite3
import hashlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any

import envutil
from security import DB_PATH, write_audit_log
from member_intel import (
    MAX_DETAIL_LEN, STORE_MESSAGE_CONTENT, TimelineEvent, add_timeline_event, get_member,
)

logger = logging.getLogger("modbot.member_incident")


# ---------------- Enums / Constants ----------------

class IncidentCategory(str, Enum):
    SPAM = "SPAM"
    FLOODING = "FLOODING"
    PHISHING = "PHISHING"
    SCAM = "SCAM"
    MALICIOUS_LINK = "MALICIOUS_LINK"
    IMPERSONATION = "IMPERSONATION"
    HARASSMENT = "HARASSMENT"
    FORBIDDEN_CONTENT = "FORBIDDEN_CONTENT"
    OTHER_SECURITY_EVENT = "OTHER_SECURITY_EVENT"


class IncidentSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"
    ARCHIVED = "ARCHIVED"


class EvidenceKind(str, Enum):
    MESSAGE = "MESSAGE"
    MEDIA_REFERENCE = "MEDIA_REFERENCE"
    ADMIN_NOTE = "ADMIN_NOTE"
    SYSTEM_RECORD = "SYSTEM_RECORD"


class CustodyAction(str, Enum):
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    EVIDENCE_REVIEWED = "EVIDENCE_REVIEWED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    INCIDENT_NOTE_ADDED = "INCIDENT_NOTE_ADDED"
    INCIDENT_CASE_LINKED = "INCIDENT_CASE_LINKED"
    ADMIN_ACTION_RECORDED = "ADMIN_ACTION_RECORDED"


class AdminAction(str, Enum):
    WARNING = "WARNING"
    MESSAGE_DELETED = "MESSAGE_DELETED"
    RESTRICTED = "RESTRICTED"
    MUTED = "MUTED"
    UNMUTED = "UNMUTED"
    BANNED = "BANNED"
    UNBANNED = "UNBANNED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"
    REPORT_GENERATED = "REPORT_GENERATED"
    DATA_PURGED = "DATA_PURGED"


VALID_CATEGORIES = frozenset(c.value for c in IncidentCategory)
VALID_SEVERITIES = frozenset(s.value for s in IncidentSeverity)
VALID_INCIDENT_STATUSES = frozenset(s.value for s in IncidentStatus)
VALID_EVIDENCE_KINDS = frozenset(k.value for k in EvidenceKind)
VALID_CUSTODY_ACTIONS = frozenset(a.value for a in CustodyAction)
VALID_ADMIN_ACTIONS = frozenset(a.value for a in AdminAction)

# Explicit lifecycle. ARCHIVED is terminal: there is no transition out of
# it, and no admin-bypass path anywhere in this module that could add one
# at runtime. Reopening is deliberately impossible so an archived record
# cannot be quietly rewritten after the fact -- a new incident is opened
# instead, which leaves both records in the trail.
INCIDENT_TRANSITIONS: Dict[str, frozenset] = {
    IncidentStatus.OPEN.value: frozenset({
        IncidentStatus.UNDER_REVIEW.value,
        IncidentStatus.CONFIRMED.value,
        IncidentStatus.DISMISSED.value,
    }),
    IncidentStatus.UNDER_REVIEW.value: frozenset({
        IncidentStatus.CONFIRMED.value,
        IncidentStatus.DISMISSED.value,
    }),
    IncidentStatus.CONFIRMED.value: frozenset({IncidentStatus.ARCHIVED.value}),
    IncidentStatus.DISMISSED.value: frozenset({IncidentStatus.ARCHIVED.value}),
    IncidentStatus.ARCHIVED.value: frozenset(),
}

TERMINAL_INCIDENT_STATUSES = frozenset({IncidentStatus.ARCHIVED.value})
RESOLVED_INCIDENT_STATUSES = frozenset({
    IncidentStatus.CONFIRMED.value, IncidentStatus.DISMISSED.value,
    IncidentStatus.ARCHIVED.value,
})

DEFAULT_SEVERITY = IncidentSeverity.LOW.value
DEFAULT_STATUS = IncidentStatus.OPEN.value

MAX_SUMMARY_LEN = 512
MAX_NOTE_LEN = 2000
MAX_CONTENT_SNAPSHOT_LEN = envutil.env_int("MEMBER_EVIDENCE_CONTENT_MAX_CHARS", 4000)
MAX_TRIGGER_RULES_LEN = 512
MAX_META_JSON_LEN = 4096

# Bounds on the aggregate reads below, so one command can never load a
# whole table into a Telegram message.
MAX_EVIDENCE_PER_VERIFY = envutil.env_int("MEMBER_MAX_EVIDENCE_PER_VERIFY", 100)
MAX_CUSTODY_ROWS = envutil.env_int("MEMBER_MAX_CUSTODY_ROWS", 200)
DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 200

# Automatic incident creation from detection results is opt-in. When off,
# detection still records security events and timeline entries as before;
# only the incident record is skipped, so an existing deployment does not
# suddenly start accumulating incidents it never asked for.
AUTO_INCIDENT_ENABLED = envutil.env_bool("MEMBER_AUTO_INCIDENT", "true")
# Minimum detection severity that opens an incident automatically.
AUTO_INCIDENT_MIN_SEVERITY = envutil.raw("MEMBER_AUTO_INCIDENT_MIN_SEVERITY", "medium").lower()
# Don't open a second automatic incident for the same account+category
# while a recent one is still unresolved -- one burst is one incident.
AUTO_INCIDENT_DEDUPE_SECONDS = envutil.env_int("MEMBER_AUTO_INCIDENT_DEDUPE_SECONDS", 900)

_DETECTION_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# detection.py's detection_type -> incident category. Anything not listed
# maps to OTHER_SECURITY_EVENT rather than being guessed into a specific
# category: calling an unknown pattern "PHISHING" would be a fabricated
# classification.
DETECTION_CATEGORY_MAP = {
    "SPAM": IncidentCategory.SPAM.value,
    "FLOOD": IncidentCategory.FLOODING.value,
    "DUPLICATE": IncidentCategory.SPAM.value,
    "DUPLICATE_MESSAGE": IncidentCategory.SPAM.value,
    "BLOCKED_LINK": IncidentCategory.MALICIOUS_LINK.value,
    "LINK": IncidentCategory.MALICIOUS_LINK.value,
    "MENTION_SPAM": IncidentCategory.SPAM.value,
    "FORBIDDEN_WORD": IncidentCategory.FORBIDDEN_CONTENT.value,
}

_DETECTION_SEVERITY_TO_INCIDENT = {
    "low": IncidentSeverity.LOW.value,
    "medium": IncidentSeverity.MEDIUM.value,
    "high": IncidentSeverity.HIGH.value,
}

# Travels with every incident render, so nobody reads "an incident
# exists" as "this account is guilty of something".
INCIDENT_DISCLAIMER = (
    "เหตุการณ์ (Incident) คือบันทึกของผู้ดูแลว่ามีสิ่งที่ถูกตรวจพบและต้องตรวจสอบ "
    "การมีเหตุการณ์ไม่ใช่ข้อสรุปว่าผู้ใช้กระทำผิด และสถานะ CONFIRMED หมายถึง "
    "'ผู้ดูแลยืนยันว่าการตรวจพบถูกต้อง' ไม่ใช่การตัดสินความผิดทางกฎหมาย"
)

INTEGRITY_DISCLAIMER = (
    "ค่าแฮช SHA-256 ใช้ตรวจว่าบันทึกหลักฐานถูกแก้ไขหรือไม่เท่านั้น "
    "ไม่ได้พิสูจน์ว่าใครเป็นผู้สร้างเนื้อหา และไม่ได้ยืนยันความถูกต้องของเนื้อหา"
)


# ---------------- Result objects ----------------

@dataclass
class IncidentResult:
    ok: bool
    reason: str
    incident_id: Optional[int] = None
    detail: str = ""


@dataclass
class EvidenceResult:
    ok: bool
    reason: str
    evidence_id: Optional[int] = None
    sha256: Optional[str] = None
    detail: str = ""


@dataclass
class IntegrityResult:
    ok: bool
    reason: str
    match: Optional[bool] = None
    stored_sha256: Optional[str] = None
    recalculated_sha256: Optional[str] = None
    verified_at: Optional[int] = None


def _ir(ok, reason, incident_id=None, detail=""):
    return IncidentResult(ok, reason, incident_id, detail)


def _er(ok, reason, evidence_id=None, sha256=None, detail=""):
    return EvidenceResult(ok, reason, evidence_id, sha256, detail)


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def member_incident_db_init() -> None:
    """Create this module's tables and indexes. Idempotent and additive:
    safe on every boot and on an existing installation."""
    conn = _conn()

    conn.execute("""CREATE TABLE IF NOT EXISTS mi_incidents (
        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        summary TEXT,
        trigger_rules TEXT,
        source TEXT NOT NULL DEFAULT 'MANUAL',
        opened_by INTEGER,
        opened_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        resolved_at INTEGER,
        resolved_by INTEGER,
        bb_case_id INTEGER,
        username_snapshot TEXT,
        display_name_snapshot TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_incidents_chat_user "
                 "ON mi_incidents (chat_id, user_id, opened_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_incidents_status "
                 "ON mi_incidents (chat_id, status, opened_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_incidents_case "
                 "ON mi_incidents (bb_case_id)")

    conn.execute("""CREATE TABLE IF NOT EXISTS mi_incident_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        author_user_id INTEGER NOT NULL,
        note TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_notes_incident "
                 "ON mi_incident_notes (incident_id, created_at)")

    # Evidence vault. The *_snapshot columns are the point of the table:
    # they freeze what the account looked like at capture time, so a later
    # username change cannot rewrite the historical context.
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_evidence (
        evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        message_id INTEGER,
        content_snapshot TEXT,
        content_omitted_reason TEXT,
        username_snapshot TEXT,
        display_name_snapshot TEXT,
        member_ref TEXT,
        media_kind TEXT,
        media_file_unique_id TEXT,
        media_mime_type TEXT,
        media_size INTEGER,
        meta_json TEXT,
        captured_at INTEGER NOT NULL,
        captured_by INTEGER,
        sha256 TEXT NOT NULL,
        last_verified_at INTEGER,
        last_verify_result TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_evidence_incident "
                 "ON mi_evidence (incident_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_evidence_chat_user "
                 "ON mi_evidence (chat_id, user_id, captured_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_evidence_message "
                 "ON mi_evidence (chat_id, message_id)")

    # Append-only chain of custody. This module issues no UPDATE and no
    # DELETE against this table anywhere.
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_custody (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id INTEGER,
        incident_id INTEGER,
        chat_id INTEGER,
        action TEXT NOT NULL,
        actor_user_id INTEGER,
        actor_kind TEXT NOT NULL DEFAULT 'system',
        detail TEXT,
        meta_json TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_custody_evidence "
                 "ON mi_custody (evidence_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_custody_incident "
                 "ON mi_custody (incident_id, created_at)")

    # Moderation-action index. `executed` records whether the bot actually
    # carried the action out (or directly observed it) -- a request that
    # failed is stored with executed=0 so the log never claims an
    # administrator did something that did not happen.
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_admin_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        target_user_id INTEGER,
        admin_user_id INTEGER,
        action TEXT NOT NULL,
        reason TEXT,
        incident_id INTEGER,
        message_id INTEGER,
        executed INTEGER NOT NULL DEFAULT 1,
        observed_by TEXT NOT NULL DEFAULT 'bot',
        detail TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_admin_actions_chat "
                 "ON mi_admin_actions (chat_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_admin_actions_target "
                 "ON mi_admin_actions (chat_id, target_user_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_admin_actions_incident "
                 "ON mi_admin_actions (incident_id)")

    conn.commit()
    conn.close()
    logger.info("MEMBER INCIDENT DATABASE: OK")


def _now(now: Optional[int] = None) -> int:
    return int(now) if now is not None else int(time.time())


def _clean(value: Optional[str], max_len: int) -> Optional[str]:
    """Untrusted free text in, inert bounded text out. Blank becomes None
    so an empty string never renders as a value that was observed."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


def _limit(limit: Optional[int]) -> int:
    """Clamps a caller-supplied row limit. Kept per-module (like each
    module's own _conn()) rather than reaching into member_intel's
    internals."""
    if limit is None:
        return DEFAULT_PAGE_LIMIT
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_LIMIT
    if value <= 0:
        return DEFAULT_PAGE_LIMIT
    return min(value, MAX_PAGE_LIMIT)


def _json_dump(meta: Optional[dict]) -> Optional[str]:
    """Canonical (sort_keys, fixed separators) bounded JSON. Byte-stability
    matters here: meta_json is inside the evidence integrity hash."""
    if not meta:
        return None
    try:
        text = json.dumps(meta, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        logger.warning("MEMBER INCIDENT | meta ไม่สามารถแปลงเป็น JSON ได้ — เก็บเป็นค่าว่าง")
        return None
    return text[:MAX_META_JSON_LEN]


def _json_load(text: Optional[str]) -> dict:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


# ---------------- Chain of custody (append-only) ----------------

def add_custody_event(action, actor_user_id: Optional[int] = None,
                      evidence_id: Optional[int] = None,
                      incident_id: Optional[int] = None,
                      chat_id: Optional[int] = None,
                      actor_kind: str = "system", detail: str = "",
                      meta: Optional[dict] = None,
                      now: Optional[int] = None) -> Optional[int]:
    """Append one handling event. Returns the row id, or None when the
    action is not a known CustodyAction -- rejected rather than stored,
    so the trail can never contain an event this module cannot explain.

    `actor_user_id` stays None unless the acting account is actually
    known; `actor_kind` is 'system' for bot-initiated handling and 'user'
    for an administrator-initiated one."""
    value = action.value if isinstance(action, CustodyAction) else str(action)
    if value not in VALID_CUSTODY_ACTIONS:
        logger.warning("CUSTODY | ไม่รู้จัก action=%r — ไม่บันทึก", value)
        return None
    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO mi_custody (evidence_id, incident_id, chat_id, action, actor_user_id, "
        "actor_kind, detail, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (evidence_id, incident_id, chat_id, value,
         int(actor_user_id) if actor_user_id is not None else None,
         "user" if actor_kind == "user" else "system",
         _clean(detail, MAX_DETAIL_LEN), _json_dump(meta), ts),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_custody_trail(evidence_id: Optional[int] = None,
                      incident_id: Optional[int] = None,
                      limit: Optional[int] = None) -> List[dict]:
    """Handling history, OLDEST first -- a custody trail is read forwards.
    Requires at least one of evidence_id/incident_id: an unfiltered dump
    of every custody row in the database is never what a caller wants and
    would leak other chats' handling history."""
    if evidence_id is None and incident_id is None:
        return []
    sql = ["SELECT * FROM mi_custody WHERE 1=1"]
    params: List[Any] = []
    if evidence_id is not None:
        sql.append("AND evidence_id=?")
        params.append(int(evidence_id))
    if incident_id is not None:
        sql.append("AND incident_id=?")
        params.append(int(incident_id))
    sql.append("ORDER BY created_at ASC, id ASC LIMIT ?")
    params.append(_limit(limit))

    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    out = []
    for row in rows:
        item = dict(row)
        item["meta"] = _json_load(item.pop("meta_json", None))
        out.append(item)
    return out


# ---------------- Phase 6: Incident engine ----------------

def create_incident(chat_id: int, user_id: int, category: str,
                    opened_by: Optional[int] = None,
                    severity: str = DEFAULT_SEVERITY, summary: str = "",
                    trigger_rules: str = "", source: str = "MANUAL",
                    now: Optional[int] = None) -> IncidentResult:
    """Open a structured incident against one observed account.

    Category and severity are validated against closed vocabularies:
    an unknown value is rejected rather than stored, so no report can
    later display a classification this module never defined.

    `opened_by` is None for a system-opened incident and is never filled
    with a guessed administrator."""
    chat_id, user_id = int(chat_id), int(user_id)
    category = (category or "").strip().upper()
    severity = (severity or DEFAULT_SEVERITY).strip().upper()
    if category not in VALID_CATEGORIES:
        return _ir(False, "INVALID_CATEGORY", detail=f"category={category!r}")
    if severity not in VALID_SEVERITIES:
        return _ir(False, "INVALID_SEVERITY", detail=f"severity={severity!r}")

    ts = _now(now)
    member = get_member(chat_id, user_id)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO mi_incidents (chat_id, user_id, category, severity, status, summary, "
        "trigger_rules, source, opened_by, opened_at, updated_at, username_snapshot, "
        "display_name_snapshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (chat_id, user_id, category, severity, DEFAULT_STATUS,
         _clean(summary, MAX_SUMMARY_LEN), _clean(trigger_rules, MAX_TRIGGER_RULES_LEN),
         "SYSTEM" if source == "SYSTEM" else "MANUAL",
         int(opened_by) if opened_by is not None else None, ts, ts,
         member["username"] if member else None,
         member["display_name"] if member else None),
    )
    incident_id = cur.lastrowid
    conn.commit()
    conn.close()

    add_custody_event(CustodyAction.INCIDENT_CREATED, actor_user_id=opened_by,
                      incident_id=incident_id, chat_id=chat_id,
                      actor_kind="user" if opened_by is not None else "system",
                      detail=f"category={category} severity={severity} source={source}",
                      now=ts)
    add_timeline_event(chat_id, user_id, TimelineEvent.INCIDENT_CREATED,
                       actor_user_id=opened_by, incident_id=incident_id,
                       detail=f"{category} ({severity})", now=ts)
    write_audit_log(chat_id, user_id, actor="user" if opened_by is not None else "system",
                    action="INCIDENT_CREATED",
                    detail=f"incident_id={incident_id} category={category} "
                           f"severity={severity} opened_by={opened_by}")
    logger.info("INCIDENT CREATED | id=%s chat=%s user=%s category=%s severity=%s",
                incident_id, chat_id, user_id, category, severity)
    return _ir(True, "OK", incident_id=incident_id)


def get_incident(incident_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM mi_incidents WHERE incident_id=?",
                       (int(incident_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_incidents(chat_id: int, user_id: Optional[int] = None,
                   status: Optional[str] = None, category: Optional[str] = None,
                   open_only: bool = False, limit: Optional[int] = None,
                   since: Optional[int] = None) -> List[dict]:
    """Incidents newest first. `status`/`category` are validated against
    the closed vocabularies and bound as parameters; an unknown value
    returns an empty list rather than being interpolated into SQL."""
    sql = ["SELECT * FROM mi_incidents WHERE chat_id=?"]
    params: List[Any] = [int(chat_id)]
    if user_id is not None:
        sql.append("AND user_id=?")
        params.append(int(user_id))
    if status is not None:
        normalized = str(status).strip().upper()
        if normalized not in VALID_INCIDENT_STATUSES:
            return []
        sql.append("AND status=?")
        params.append(normalized)
    if category is not None:
        normalized = str(category).strip().upper()
        if normalized not in VALID_CATEGORIES:
            return []
        sql.append("AND category=?")
        params.append(normalized)
    if open_only:
        unresolved = sorted(VALID_INCIDENT_STATUSES - RESOLVED_INCIDENT_STATUSES)
        sql.append("AND status IN (%s)" % ",".join("?" for _ in unresolved))
        params.extend(unresolved)
    if since is not None:
        sql.append("AND opened_at >= ?")
        params.append(int(since))
    sql.append("ORDER BY opened_at DESC, incident_id DESC LIMIT ?")
    params.append(_limit(limit))

    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_incident_status(incident_id: int, new_status: str, actor_user_id: int,
                           note: str = "", now: Optional[int] = None) -> IncidentResult:
    """Advance an incident along the documented lifecycle.

    OPEN -> UNDER_REVIEW -> CONFIRMED | DISMISSED -> ARCHIVED

    An illegal transition is refused with INVALID_TRANSITION; ARCHIVED is
    terminal and has no outgoing transition. There is no actor, role or
    flag anywhere in this module that can bypass INCIDENT_TRANSITIONS."""
    new_status = (new_status or "").strip().upper()
    if new_status not in VALID_INCIDENT_STATUSES:
        return _ir(False, "INVALID_STATUS", detail=f"status={new_status!r}")

    incident = get_incident(incident_id)
    if not incident:
        return _ir(False, "INCIDENT_NOT_FOUND")

    current = incident["status"]
    if current == new_status:
        return _ir(False, "NO_CHANGE", incident_id=incident["incident_id"],
                   detail=f"status={current}")
    allowed = INCIDENT_TRANSITIONS.get(current, frozenset())
    if new_status not in allowed:
        return _ir(False, "INVALID_TRANSITION", incident_id=incident["incident_id"],
                   detail=f"{current} -> {new_status}")

    ts = _now(now)
    resolved = new_status in RESOLVED_INCIDENT_STATUSES
    conn = _conn()
    conn.execute(
        "UPDATE mi_incidents SET status=?, updated_at=?, "
        "resolved_at = CASE WHEN ? THEN COALESCE(resolved_at, ?) ELSE resolved_at END, "
        "resolved_by = CASE WHEN ? THEN COALESCE(resolved_by, ?) ELSE resolved_by END "
        "WHERE incident_id=?",
        (new_status, ts, 1 if resolved else 0, ts, 1 if resolved else 0,
         int(actor_user_id), int(incident_id)),
    )
    conn.commit()
    conn.close()

    detail = f"{current} -> {new_status}"
    if note:
        add_incident_note(incident_id, actor_user_id, note, now=ts)
    add_custody_event(CustodyAction.INCIDENT_STATUS_CHANGED, actor_user_id=actor_user_id,
                      incident_id=incident_id, chat_id=incident["chat_id"],
                      actor_kind="user", detail=detail, now=ts)
    event = (TimelineEvent.INCIDENT_RESOLVED if resolved
             else TimelineEvent.INCIDENT_STATUS_CHANGED)
    add_timeline_event(incident["chat_id"], incident["user_id"], event,
                       actor_user_id=actor_user_id, incident_id=incident_id,
                       detail=detail, now=ts)
    record_admin_action(incident["chat_id"], AdminAction.INCIDENT_STATUS_CHANGED,
                        target_user_id=incident["user_id"], admin_user_id=actor_user_id,
                        incident_id=incident_id, reason=detail, now=ts)
    logger.info("INCIDENT STATUS | id=%s %s by=%s", incident_id, detail, actor_user_id)
    return _ir(True, "OK", incident_id=int(incident_id), detail=detail)


def add_incident_note(incident_id: int, author_user_id: int, note: str,
                      now: Optional[int] = None) -> IncidentResult:
    """Attach an investigator note. Notes are inert text: length-capped,
    stored, rendered. Never evaluated and never read by any check."""
    incident = get_incident(incident_id)
    if not incident:
        return _ir(False, "INCIDENT_NOT_FOUND")
    text = _clean(note, MAX_NOTE_LEN)
    if not text:
        return _ir(False, "EMPTY_NOTE")

    ts = _now(now)
    conn = _conn()
    conn.execute(
        "INSERT INTO mi_incident_notes (incident_id, author_user_id, note, created_at) "
        "VALUES (?, ?, ?, ?)",
        (int(incident_id), int(author_user_id), text, ts),
    )
    conn.execute("UPDATE mi_incidents SET updated_at=? WHERE incident_id=?",
                 (ts, int(incident_id)))
    conn.commit()
    conn.close()

    add_custody_event(CustodyAction.INCIDENT_NOTE_ADDED, actor_user_id=author_user_id,
                      incident_id=incident_id, chat_id=incident["chat_id"],
                      actor_kind="user", detail=f"chars={len(text)}", now=ts)
    return _ir(True, "OK", incident_id=int(incident_id))


def list_incident_notes(incident_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM mi_incident_notes WHERE incident_id=? "
        "ORDER BY created_at ASC, id ASC LIMIT ?",
        (int(incident_id), _limit(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Phase 12: Case linking ----------------

def link_case(incident_id: int, bb_case_id: int, actor_user_id: int,
              now: Optional[int] = None) -> IncidentResult:
    """Reference an existing bb_case from this incident.

    Integration only, in one direction: the Case keeps owning its own
    workflow and state machine (bb_case.py), and this link can never
    create a Case, change a Case's status, or widen any bug-bounty
    authorization. The Case must already exist -- verified through
    bb_case.get_case(), not by touching its table."""
    incident = get_incident(incident_id)
    if not incident:
        return _ir(False, "INCIDENT_NOT_FOUND")
    try:
        from bb_case import get_case
    except ImportError:  # pragma: no cover - bb_case ships with the bot
        return _ir(False, "CASE_LAYER_UNAVAILABLE")
    case = get_case(int(bb_case_id))
    if not case:
        return _ir(False, "CASE_NOT_FOUND", detail=f"bb_case_id={bb_case_id}")

    ts = _now(now)
    conn = _conn()
    conn.execute("UPDATE mi_incidents SET bb_case_id=?, updated_at=? WHERE incident_id=?",
                 (int(bb_case_id), ts, int(incident_id)))
    conn.commit()
    conn.close()

    add_custody_event(CustodyAction.INCIDENT_CASE_LINKED, actor_user_id=actor_user_id,
                      incident_id=incident_id, chat_id=incident["chat_id"],
                      actor_kind="user", detail=f"bb_case_id={bb_case_id}", now=ts)
    write_audit_log(incident["chat_id"], incident["user_id"], actor="user",
                    action="INCIDENT_CASE_LINKED",
                    detail=f"incident_id={incident_id} bb_case_id={bb_case_id} "
                           f"actor={actor_user_id}")
    return _ir(True, "OK", incident_id=int(incident_id), detail=f"bb_case_id={bb_case_id}")


# ---------------- Phase 7/8: Evidence vault + integrity ----------------

# Fields covered by the integrity hash, in a fixed order. Changing this
# tuple changes every future hash, so it is deliberately explicit rather
# than "whatever columns exist": an added column must be reviewed before
# it can affect integrity verification.
_HASHED_FIELDS = (
    "chat_id", "user_id", "kind", "message_id", "content_snapshot",
    "content_omitted_reason", "username_snapshot", "display_name_snapshot",
    "member_ref", "media_kind", "media_file_unique_id", "media_mime_type",
    "media_size", "meta_json", "captured_at", "captured_by",
)

# Version tag inside the hashed payload. An evidence record hashed under
# an older layout stays verifiable because its stored hash was computed
# over its own version tag.
EVIDENCE_HASH_VERSION = "mi-evidence-v1"


def _canonical_payload(record: Dict[str, Any]) -> str:
    """Byte-stable canonical JSON over the hashed fields only.

    sort_keys + fixed separators + explicit field list means the same
    record always produces the same bytes, on any Python version and
    regardless of column order -- which is what makes a later mismatch
    meaningful rather than an artifact of serialisation."""
    payload = {"_v": EVIDENCE_HASH_VERSION}
    for name in _HASHED_FIELDS:
        payload[name] = record.get(name)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _evidence_hash(record: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_payload(record).encode("utf-8")).hexdigest()


def capture_evidence(chat_id: int, user_id: int, kind: str = EvidenceKind.MESSAGE.value,
                     incident_id: Optional[int] = None,
                     message_id: Optional[int] = None,
                     content: Optional[str] = None,
                     username: Optional[str] = None,
                     display_name: Optional[str] = None,
                     media_kind: Optional[str] = None,
                     media_file_unique_id: Optional[str] = None,
                     media_mime_type: Optional[str] = None,
                     media_size: Optional[int] = None,
                     captured_by: Optional[int] = None,
                     meta: Optional[dict] = None,
                     now: Optional[int] = None) -> EvidenceResult:
    """Record one evidence snapshot and its integrity hash.

    Snapshots, not references: the username and display name observed at
    capture time are frozen into this row, so a rename months later
    cannot change what the record says the account was called when the
    message was sent.

    Message content is stored only when MEMBER_STORE_MESSAGE_CONTENT is
    enabled (default on, configurable per deployment). When it is off the
    row still carries the structural facts -- chat, account, message id,
    timestamps, name snapshots, hash -- and content_omitted_reason
    explains the gap, so a report never implies the message was empty.

    Media: only Telegram's own file references and metadata are stored.
    No media bytes are downloaded, hashed or persisted by this module,
    and a file_unique_id is not a download link."""
    chat_id, user_id = int(chat_id), int(user_id)
    kind = (kind or EvidenceKind.MESSAGE.value).strip().upper()
    if kind not in VALID_EVIDENCE_KINDS:
        return _er(False, "INVALID_EVIDENCE_KIND", detail=f"kind={kind!r}")
    if incident_id is not None and not get_incident(incident_id):
        return _er(False, "INCIDENT_NOT_FOUND", detail=f"incident_id={incident_id}")

    ts = _now(now)
    # Prefer the caller's freshly observed identity; fall back to the
    # registry so a snapshot is never left blank when we do know the name.
    member = get_member(chat_id, user_id)
    username_snapshot = _clean(username, 64) or (member["username"] if member else None)
    if username_snapshot:
        username_snapshot = username_snapshot.lstrip("@") or None
    display_snapshot = _clean(display_name, 256) or (member["display_name"] if member else None)
    member_ref = member["member_ref"] if member else None

    content_snapshot = None
    omitted_reason = None
    if content is not None and str(content).strip():
        if STORE_MESSAGE_CONTENT:
            content_snapshot = str(content)[:MAX_CONTENT_SNAPSHOT_LEN]
            if len(str(content)) > MAX_CONTENT_SNAPSHOT_LEN:
                omitted_reason = f"TRUNCATED_AT_{MAX_CONTENT_SNAPSHOT_LEN}_CHARS"
        else:
            omitted_reason = "CONTENT_RETENTION_DISABLED"
    elif content is None:
        omitted_reason = "NO_TEXT_CONTENT"

    record = {
        "chat_id": chat_id,
        "user_id": user_id,
        "kind": kind,
        "message_id": int(message_id) if message_id is not None else None,
        "content_snapshot": content_snapshot,
        "content_omitted_reason": omitted_reason,
        "username_snapshot": username_snapshot,
        "display_name_snapshot": display_snapshot,
        "member_ref": member_ref,
        "media_kind": _clean(media_kind, 32),
        "media_file_unique_id": _clean(media_file_unique_id, 128),
        "media_mime_type": _clean(media_mime_type, 128),
        "media_size": int(media_size) if media_size is not None else None,
        "meta_json": _json_dump(meta),
        "captured_at": ts,
        "captured_by": int(captured_by) if captured_by is not None else None,
    }
    sha256_hex = _evidence_hash(record)

    conn = _conn()
    cur = conn.execute(
        "INSERT INTO mi_evidence (incident_id, chat_id, user_id, kind, message_id, "
        "content_snapshot, content_omitted_reason, username_snapshot, display_name_snapshot, "
        "member_ref, media_kind, media_file_unique_id, media_mime_type, media_size, "
        "meta_json, captured_at, captured_by, sha256) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (incident_id, record["chat_id"], record["user_id"], record["kind"],
         record["message_id"], record["content_snapshot"], record["content_omitted_reason"],
         record["username_snapshot"], record["display_name_snapshot"], record["member_ref"],
         record["media_kind"], record["media_file_unique_id"], record["media_mime_type"],
         record["media_size"], record["meta_json"], record["captured_at"],
         record["captured_by"], sha256_hex),
    )
    evidence_id = cur.lastrowid
    conn.commit()
    conn.close()

    add_custody_event(CustodyAction.EVIDENCE_CREATED, actor_user_id=captured_by,
                      evidence_id=evidence_id, incident_id=incident_id, chat_id=chat_id,
                      actor_kind="user" if captured_by is not None else "system",
                      detail=f"kind={kind} sha256={sha256_hex[:16]}", now=ts)
    if incident_id is not None:
        add_custody_event(CustodyAction.EVIDENCE_LINKED, actor_user_id=captured_by,
                          evidence_id=evidence_id, incident_id=incident_id, chat_id=chat_id,
                          actor_kind="user" if captured_by is not None else "system",
                          detail=f"incident_id={incident_id}", now=ts)
    add_timeline_event(chat_id, user_id, TimelineEvent.EVIDENCE_CAPTURED,
                       actor_user_id=captured_by, message_id=message_id,
                       incident_id=incident_id,
                       detail=f"evidence_id={evidence_id} kind={kind}", now=ts)
    logger.info("EVIDENCE CAPTURED | id=%s chat=%s user=%s kind=%s incident=%s",
                evidence_id, chat_id, user_id, kind, incident_id)
    return _er(True, "OK", evidence_id=evidence_id, sha256=sha256_hex)


def get_evidence(evidence_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM mi_evidence WHERE evidence_id=?",
                       (int(evidence_id),)).fetchone()
    conn.close()
    if not row:
        return None
    item = dict(row)
    item["meta"] = _json_load(item.get("meta_json"))
    return item


def list_evidence(incident_id: Optional[int] = None, chat_id: Optional[int] = None,
                  user_id: Optional[int] = None, limit: Optional[int] = None) -> List[dict]:
    """Evidence records, newest first. Requires at least an incident_id or
    a chat_id: an unfiltered query would return other chats' evidence."""
    if incident_id is None and chat_id is None:
        return []
    sql = ["SELECT * FROM mi_evidence WHERE 1=1"]
    params: List[Any] = []
    if incident_id is not None:
        sql.append("AND incident_id=?")
        params.append(int(incident_id))
    if chat_id is not None:
        sql.append("AND chat_id=?")
        params.append(int(chat_id))
    if user_id is not None:
        sql.append("AND user_id=?")
        params.append(int(user_id))
    sql.append("ORDER BY captured_at DESC, evidence_id DESC LIMIT ?")
    params.append(_limit(limit))

    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    out = []
    for row in rows:
        item = dict(row)
        item["meta"] = _json_load(item.get("meta_json"))
        out.append(item)
    return out


def verify_evidence(evidence_id: int, actor_user_id: Optional[int] = None,
                    now: Optional[int] = None) -> IntegrityResult:
    """Recompute the integrity hash from the stored record and compare it
    with the hash written at capture time.

    MATCH means the stored record is byte-identical to what was captured.
    MISMATCH means the row changed after capture -- a manual database
    edit, a partial write, or corruption. It does NOT identify who
    changed it, and a MATCH does not prove who created the content or
    that the content is truthful (see INTEGRITY_DISCLAIMER).

    The verification result and timestamp are recorded on the row and
    appended to the custody trail, so "we checked, and it was intact on
    this date" is itself part of the record. Those two columns are
    excluded from _HASHED_FIELDS by design -- verifying evidence must not
    change its own hash."""
    record = get_evidence(evidence_id)
    if not record:
        return IntegrityResult(False, "EVIDENCE_NOT_FOUND")
    stored = record.get("sha256")
    if not stored:
        return IntegrityResult(False, "NO_STORED_HASH")

    recalculated = _evidence_hash(record)
    match = recalculated == stored
    ts = _now(now)
    result_text = "MATCH" if match else "MISMATCH"

    conn = _conn()
    conn.execute(
        "UPDATE mi_evidence SET last_verified_at=?, last_verify_result=? WHERE evidence_id=?",
        (ts, result_text, int(evidence_id)),
    )
    conn.commit()
    conn.close()

    add_custody_event(CustodyAction.EVIDENCE_VERIFIED, actor_user_id=actor_user_id,
                      evidence_id=int(evidence_id), incident_id=record.get("incident_id"),
                      chat_id=record.get("chat_id"),
                      actor_kind="user" if actor_user_id is not None else "system",
                      detail=f"result={result_text}", now=ts)
    write_audit_log(record["chat_id"], record["user_id"],
                    actor="user" if actor_user_id is not None else "system",
                    action="EVIDENCE_VERIFIED",
                    detail=f"evidence_id={evidence_id} result={result_text}")
    if not match:
        logger.warning("EVIDENCE INTEGRITY MISMATCH | evidence_id=%s", evidence_id)
    return IntegrityResult(True, "OK", match=match, stored_sha256=stored,
                           recalculated_sha256=recalculated, verified_at=ts)


def verify_incident_evidence(incident_id: int, actor_user_id: Optional[int] = None,
                             now: Optional[int] = None) -> dict:
    """Verify every evidence record attached to one incident. Returns the
    per-record outcomes plus counts, so an admin sees "12 intact, 1
    mismatch" rather than having to check each one."""
    records = list_evidence(incident_id=int(incident_id), limit=MAX_EVIDENCE_PER_VERIFY)
    results = []
    intact = mismatched = failed = 0
    for record in records:
        outcome = verify_evidence(record["evidence_id"], actor_user_id=actor_user_id, now=now)
        if not outcome.ok:
            failed += 1
        elif outcome.match:
            intact += 1
        else:
            mismatched += 1
        results.append({"evidence_id": record["evidence_id"], "ok": outcome.ok,
                        "reason": outcome.reason, "match": outcome.match})
    return {"incident_id": int(incident_id), "checked": len(records), "intact": intact,
            "mismatched": mismatched, "failed": failed, "results": results,
            "disclaimer": INTEGRITY_DISCLAIMER}


def mark_evidence_reviewed(evidence_id: int, actor_user_id: int, note: str = "",
                           now: Optional[int] = None) -> bool:
    """Append a 'reviewed' custody event. Deliberately does not mutate the
    evidence row: a review is something that happened TO the evidence, so
    it belongs in the append-only trail, not in the hashed record."""
    record = get_evidence(evidence_id)
    if not record:
        return False
    add_custody_event(CustodyAction.EVIDENCE_REVIEWED, actor_user_id=actor_user_id,
                      evidence_id=int(evidence_id), incident_id=record.get("incident_id"),
                      chat_id=record.get("chat_id"), actor_kind="user",
                      detail=_clean(note, MAX_DETAIL_LEN) or "", now=now)
    return True


def mark_evidence_exported(evidence_ids: List[int], actor_user_id: int,
                           destination: str = "telegram",
                           now: Optional[int] = None) -> int:
    """Append an 'exported' custody event per record. Called by the export
    path so the trail answers "who took a copy of this, and when" --
    which is the question a custody log exists to answer."""
    count = 0
    chat_id = 0
    for evidence_id in evidence_ids or []:
        record = get_evidence(evidence_id)
        if not record:
            continue
        chat_id = record.get("chat_id") or chat_id
        add_custody_event(CustodyAction.EVIDENCE_EXPORTED, actor_user_id=actor_user_id,
                          evidence_id=int(evidence_id),
                          incident_id=record.get("incident_id"),
                          chat_id=record.get("chat_id"), actor_kind="user",
                          detail=f"destination={_clean(destination, 64) or 'unknown'}",
                          now=now)
        count += 1
    if count:
        write_audit_log(chat_id, None, actor="user", action="EVIDENCE_EXPORTED",
                        detail=f"actor={actor_user_id} count={count} dest={destination}")
    return count


# ---------------- Phase 10: Admin action audit ----------------

def record_admin_action(chat_id: int, action, target_user_id: Optional[int] = None,
                        admin_user_id: Optional[int] = None, reason: str = "",
                        incident_id: Optional[int] = None,
                        message_id: Optional[int] = None, executed: bool = True,
                        observed_by: str = "bot", detail: str = "",
                        now: Optional[int] = None) -> Optional[int]:
    """Record one moderation/administrative action.

    Honesty rules baked in:
      - `admin_user_id` must be the account the bot actually observed
        acting, or None. A None here means "the bot performed this
        automatically" (or could not observe an actor) -- it is never
        back-filled with a plausible administrator.
      - `executed=False` records an ATTEMPT that did not take effect (the
        bot lacked permission, Telegram refused). The row is kept because
        a failed restriction is itself relevant, but it never reads as
        though the action succeeded.
      - `observed_by` is 'bot' when the bot itself performed or directly
        observed the action, and 'report' when it was recorded from a
        human's account of events.

    Writes the global audit_log entry too (security.write_audit_log), so
    this table stays an index over moderation actions rather than a
    competing audit system."""
    value = action.value if isinstance(action, AdminAction) else str(action).strip().upper()
    if value not in VALID_ADMIN_ACTIONS:
        logger.warning("ADMIN ACTION | ไม่รู้จัก action=%r — ไม่บันทึก", value)
        return None

    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO mi_admin_actions (chat_id, target_user_id, admin_user_id, action, "
        "reason, incident_id, message_id, executed, observed_by, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(chat_id),
         int(target_user_id) if target_user_id is not None else None,
         int(admin_user_id) if admin_user_id is not None else None,
         value, _clean(reason, MAX_DETAIL_LEN), incident_id, message_id,
         1 if executed else 0,
         "report" if observed_by == "report" else "bot",
         _clean(detail, MAX_DETAIL_LEN), ts),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()

    write_audit_log(int(chat_id), target_user_id,
                    actor="user" if admin_user_id is not None else "system",
                    action=f"ADMIN_{value}",
                    detail=f"admin={admin_user_id if admin_user_id is not None else 'system'} "
                           f"executed={bool(executed)} incident={incident_id} "
                           f"reason={_clean(reason, 200) or '-'}")
    add_custody_event(CustodyAction.ADMIN_ACTION_RECORDED, actor_user_id=admin_user_id,
                      incident_id=incident_id, chat_id=int(chat_id),
                      actor_kind="user" if admin_user_id is not None else "system",
                      detail=f"action={value} executed={bool(executed)}", now=ts)
    return row_id


def list_admin_actions(chat_id: int, target_user_id: Optional[int] = None,
                       admin_user_id: Optional[int] = None,
                       incident_id: Optional[int] = None,
                       limit: Optional[int] = None,
                       since: Optional[int] = None) -> List[dict]:
    sql = ["SELECT * FROM mi_admin_actions WHERE chat_id=?"]
    params: List[Any] = [int(chat_id)]
    if target_user_id is not None:
        sql.append("AND target_user_id=?")
        params.append(int(target_user_id))
    if admin_user_id is not None:
        sql.append("AND admin_user_id=?")
        params.append(int(admin_user_id))
    if incident_id is not None:
        sql.append("AND incident_id=?")
        params.append(int(incident_id))
    if since is not None:
        sql.append("AND created_at >= ?")
        params.append(int(since))
    sql.append("ORDER BY created_at DESC, id DESC LIMIT ?")
    params.append(_limit(limit))

    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Automatic incident creation from detection ----------------

def _recent_open_incident(chat_id: int, user_id: int, category: str,
                          since: int) -> Optional[dict]:
    conn = _conn()
    unresolved = sorted(VALID_INCIDENT_STATUSES - RESOLVED_INCIDENT_STATUSES)
    row = conn.execute(
        "SELECT * FROM mi_incidents WHERE chat_id=? AND user_id=? AND category=? "
        "AND opened_at >= ? AND status IN (%s) "
        "ORDER BY opened_at DESC LIMIT 1" % ",".join("?" for _ in unresolved),
        [int(chat_id), int(user_id), category, int(since)] + unresolved,
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def incident_from_detection(chat_id: int, user_id: int, detection_type: str,
                            severity: str, reason: str = "",
                            message_id: Optional[int] = None,
                            content: Optional[str] = None,
                            username: Optional[str] = None,
                            display_name: Optional[str] = None,
                            now: Optional[int] = None) -> IncidentResult:
    """Open a system incident from one detection.py DetectionResult and
    attach the triggering message as evidence.

    Deterministic and conservative:
      - Disabled entirely unless MEMBER_AUTO_INCIDENT is on.
      - Only detections at or above MEMBER_AUTO_INCIDENT_MIN_SEVERITY.
      - An unmapped detection_type becomes OTHER_SECURITY_EVENT rather
        than being guessed into PHISHING/SCAM/etc.
      - Deduped: while a recent unresolved incident of the same category
        exists for the same account, the message is attached to THAT
        incident instead of opening a new one, so a 20-message flood is
        one incident with 20 evidence records.
      - opened_by stays None: the bot opened it, not an administrator."""
    if not AUTO_INCIDENT_ENABLED:
        return _ir(False, "AUTO_INCIDENT_DISABLED")

    sev_key = (severity or "low").strip().lower()
    threshold = _DETECTION_SEVERITY_ORDER.get(AUTO_INCIDENT_MIN_SEVERITY, 1)
    if _DETECTION_SEVERITY_ORDER.get(sev_key, 0) < threshold:
        return _ir(False, "BELOW_SEVERITY_THRESHOLD", detail=f"severity={sev_key}")

    category = DETECTION_CATEGORY_MAP.get((detection_type or "").strip().upper(),
                                          IncidentCategory.OTHER_SECURITY_EVENT.value)
    ts = _now(now)
    existing = _recent_open_incident(chat_id, user_id, category,
                                     ts - max(0, AUTO_INCIDENT_DEDUPE_SECONDS))
    if existing:
        incident_id = existing["incident_id"]
        capture_evidence(chat_id, user_id, kind=EvidenceKind.MESSAGE.value,
                         incident_id=incident_id, message_id=message_id, content=content,
                         username=username, display_name=display_name,
                         meta={"detection_type": detection_type, "severity": sev_key,
                               "reason": reason[:MAX_DETAIL_LEN] if reason else ""},
                         now=ts)
        return _ir(True, "APPENDED_TO_EXISTING", incident_id=incident_id,
                   detail=f"category={category}")

    result = create_incident(
        chat_id, user_id, category, opened_by=None,
        severity=_DETECTION_SEVERITY_TO_INCIDENT.get(sev_key, IncidentSeverity.LOW.value),
        summary=reason, trigger_rules=f"detection:{(detection_type or '').strip().upper()}",
        source="SYSTEM", now=ts,
    )
    if not result.ok:
        return result
    capture_evidence(chat_id, user_id, kind=EvidenceKind.MESSAGE.value,
                     incident_id=result.incident_id, message_id=message_id, content=content,
                     username=username, display_name=display_name,
                     meta={"detection_type": detection_type, "severity": sev_key,
                           "reason": reason[:MAX_DETAIL_LEN] if reason else ""},
                     now=ts)
    return result


# ---------------- Aggregate read for reporting ----------------

def get_incident_bundle(incident_id: int, evidence_limit: Optional[int] = None) -> Optional[dict]:
    """One incident with everything attached to it, shaped for reporting:
    the incident record, its notes, its evidence, the administrative
    actions taken, and the custody trail."""
    incident = get_incident(incident_id)
    if not incident:
        return None
    evidence = list_evidence(incident_id=int(incident_id), limit=evidence_limit)
    return {
        "incident": incident,
        "notes": list_incident_notes(int(incident_id)),
        "evidence": evidence,
        "evidence_count": len(evidence),
        "admin_actions": list_admin_actions(incident["chat_id"],
                                            incident_id=int(incident_id)),
        "custody": get_custody_trail(incident_id=int(incident_id), limit=MAX_CUSTODY_ROWS),
        "disclaimer": INCIDENT_DISCLAIMER,
    }


def get_incident_stats(chat_id: int, since: Optional[int] = None) -> dict:
    """Counts by status/category/severity for one chat -- the summary a
    dashboard or report header needs without loading every row."""
    params: List[Any] = [int(chat_id)]
    clause = ""
    if since is not None:
        clause = " AND opened_at >= ?"
        params.append(int(since))
    conn = _conn()
    by_status = conn.execute(
        "SELECT status, COUNT(*) AS n FROM mi_incidents WHERE chat_id=?" + clause +
        " GROUP BY status ORDER BY n DESC", params).fetchall()
    by_category = conn.execute(
        "SELECT category, COUNT(*) AS n FROM mi_incidents WHERE chat_id=?" + clause +
        " GROUP BY category ORDER BY n DESC", params).fetchall()
    by_severity = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM mi_incidents WHERE chat_id=?" + clause +
        " GROUP BY severity ORDER BY n DESC", params).fetchall()
    evidence_row = conn.execute(
        "SELECT COUNT(*) AS n FROM mi_evidence WHERE chat_id=?", (int(chat_id),)).fetchone()
    conn.close()
    return {
        "chat_id": int(chat_id),
        "by_status": {r["status"]: r["n"] for r in by_status},
        "by_category": {r["category"]: r["n"] for r in by_category},
        "by_severity": {r["severity"]: r["n"] for r in by_severity},
        "evidence_total": evidence_row["n"] if evidence_row else 0,
    }
