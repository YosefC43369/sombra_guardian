"""
redteam.py — Phase 11: Red Team Assessment & Adversary Simulation.

A CASE-DRIVEN, RECORD-KEEPING and AUTHORIZATION-ENFORCEMENT system for
authorized red-team engagements. It manages engagements, Rules of
Engagement (RoE), the in-scope target registry, findings, attack-path
correlation, evidence, the activity timeline, the review queue and
reporting hand-off.

WHAT THIS MODULE IS NOT, and must never become:
  - It launches NO attacks. There is no exploit, payload, C2, scanner,
    credential attack, DoS, lateral-movement or network-probing code
    anywhere in it. It opens no sockets. Any actual (passive) network
    check is performed only by the existing security_testing.py engine
    through its own gate; this module records and governs, it does not
    act on targets.
  - It never auto-promotes a finding to VERIFIED_RISK, never concludes a
    target is in scope on its own, and never confirms exploitability.
    Those are human decisions, enforced here as state-machine gates that
    require a named operator and (for VERIFIED_RISK) attached evidence.

AUTHORIZATION MODEL (reuse, not reinvention):
An Engagement is backed by a scope_policy Program. The in-scope decision
for any target is delegated ENTIRELY to scope_policy.evaluate_target()
— the same deterministic ALLOW/DENY engine the Bug-Bounty stack uses,
which already knows how to match domains / IPs / CIDRs / URLs against
INCLUDE/EXCLUDE rules under a reviewed, in-force Authorization. This
module adds the red-team RoE layer ON TOP of that gate:

    engagement exists
      -> engagement status is operational (AUTHORIZED / LIMITED_SCOPE)
      -> kill-switch not engaged (not TERMINATED)
      -> now within the authorized testing window
      -> operator is on the engagement's authorized-operator list
      -> scope_policy.evaluate_target() ALLOWS the target
    == RoE ALLOW.  Any failure => DENY, fail-closed, deny-by-default.

There is NO `is_admin` input in the RoE gate: Telegram-admin status can
never widen scope or authorization by one byte (identical stance to
security_testing.py / bb_scan.py).

Design constraints (matches scope_policy.py / findings.py / bb_case.py /
member_incident.py / bb_scan.py):
  - Standard library only, plus scope_policy + security. No new
    dependency, no shell, no eval/exec, no background threads.
  - Reuses security.DB_PATH and security.write_audit_log(). No second
    database, no second audit system.
  - CREATE TABLE IF NOT EXISTS only; idempotent init; never a
    destructive migration.
  - Every query parameterized. Targets, notes, tool output and details
    are inert data: stored, length-capped, rendered as text, never
    interpreted, never used in an authorization decision.
  - The chain-of-custody table is append-only: this module issues no
    UPDATE and no DELETE against it.
"""

import re
import json
import time
import sqlite3
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any

import envutil
from security import DB_PATH, write_audit_log
import scope_policy
from scope_policy import (
    evaluate_target, get_program, create_program, set_program_status,
    import_authorization, review_authorization, revoke_authorization,
    add_scope_rule, list_scope_rules, ProgramStatus, RuleType, TargetType,
    VALID_RULE_TYPES, VALID_TARGET_TYPES,
)

logger = logging.getLogger("modbot.redteam")


# ---------------- Enums / closed vocabularies ----------------

class EngagementStatus(str, Enum):
    """RoE lifecycle. Only AUTHORIZED and LIMITED_SCOPE permit any
    operation; TERMINATED and EXPIRED are terminal (the kill-switch and
    the clock, respectively)."""
    PENDING_APPROVAL = "PENDING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    LIMITED_SCOPE = "LIMITED_SCOPE"
    PAUSED = "PAUSED"
    TERMINATED = "TERMINATED"
    EXPIRED = "EXPIRED"


# Statuses under which operations may proceed (subject to the rest of
# the gate). Everything else blocks.
OPERATIONAL_STATUSES = frozenset({EngagementStatus.AUTHORIZED.value,
                                  EngagementStatus.LIMITED_SCOPE.value})
TERMINAL_STATUSES = frozenset({EngagementStatus.TERMINATED.value,
                               EngagementStatus.EXPIRED.value})

ENGAGEMENT_TRANSITIONS: Dict[str, frozenset] = {
    EngagementStatus.PENDING_APPROVAL.value: frozenset({
        EngagementStatus.AUTHORIZED.value, EngagementStatus.LIMITED_SCOPE.value,
        EngagementStatus.TERMINATED.value}),
    EngagementStatus.AUTHORIZED.value: frozenset({
        EngagementStatus.LIMITED_SCOPE.value, EngagementStatus.PAUSED.value,
        EngagementStatus.TERMINATED.value, EngagementStatus.EXPIRED.value}),
    EngagementStatus.LIMITED_SCOPE.value: frozenset({
        EngagementStatus.AUTHORIZED.value, EngagementStatus.PAUSED.value,
        EngagementStatus.TERMINATED.value, EngagementStatus.EXPIRED.value}),
    EngagementStatus.PAUSED.value: frozenset({
        EngagementStatus.AUTHORIZED.value, EngagementStatus.LIMITED_SCOPE.value,
        EngagementStatus.TERMINATED.value, EngagementStatus.EXPIRED.value}),
    EngagementStatus.TERMINATED.value: frozenset(),
    EngagementStatus.EXPIRED.value: frozenset(),
}


class AssetCategory(str, Enum):
    IN_SCOPE_INFRASTRUCTURE = "IN_SCOPE_INFRASTRUCTURE"
    EXTERNAL_PERIMETER = "EXTERNAL_PERIMETER"
    AUTHORIZED_APPLICATION = "AUTHORIZED_APPLICATION"
    CLOUD_TENANT = "CLOUD_TENANT"
    SIMULATED_THREAT_VECTOR = "SIMULATED_THREAT_VECTOR"
    DEFENSIVE_TELEMETRY_SOURCE = "DEFENSIVE_TELEMETRY_SOURCE"


class FindingClass(str, Enum):
    """The Phase 6 classification. Deliberately ordered from weakest to
    strongest claim; promotion toward VERIFIED_RISK is gated."""
    UNKNOWN = "UNKNOWN"
    LEAD = "LEAD"
    EXPOSURE = "EXPOSURE"
    VERIFIED_RISK = "VERIFIED_RISK"


# VERIFIED_RISK is the only classification a human may set, and only with
# evidence. Everything else can be set freely during triage. This is the
# "AI/automation must never promote LEAD/EXPOSURE -> VERIFIED_RISK
# without proof and human review" rule, encoded.
HUMAN_ONLY_CLASSES = frozenset({FindingClass.VERIFIED_RISK.value})


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VectorStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNVERIFIED = "UNVERIFIED"
    REMEDIATED = "REMEDIATED"


class TimelineKind(str, Enum):
    """Phase 11 distinction: an observed event on a host, an action a
    human operator took, and an administrative/RoE change are three
    different things and are never conflated."""
    OBSERVED_HOST_EVENT = "OBSERVED_HOST_EVENT"
    OPERATOR_ACTION = "OPERATOR_ACTION"
    ADMINISTRATIVE_CHANGE = "ADMINISTRATIVE_CHANGE"


class EvidenceKind(str, Enum):
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    COMMAND_LOG = "COMMAND_LOG"
    SCREENSHOT_REF = "SCREENSHOT_REF"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    OBSERVATION = "OBSERVATION"
    OTHER = "OTHER"


class CustodyAction(str, Enum):
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_RECLASSIFIED = "FINDING_RECLASSIFIED"
    REVIEW_DECISION = "REVIEW_DECISION"
    ENGAGEMENT_STATUS_CHANGED = "ENGAGEMENT_STATUS_CHANGED"


class ReviewStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"


class ReviewPriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


VALID_ASSET_CATEGORIES = frozenset(c.value for c in AssetCategory)
VALID_FINDING_CLASSES = frozenset(c.value for c in FindingClass)
VALID_SEVERITIES = frozenset(s.value for s in Severity)
VALID_CONFIDENCE = frozenset(c.value for c in Confidence)
VALID_VECTOR_STATUSES = frozenset(s.value for s in VectorStatus)
VALID_TIMELINE_KINDS = frozenset(k.value for k in TimelineKind)
VALID_EVIDENCE_KINDS = frozenset(k.value for k in EvidenceKind)
VALID_CUSTODY_ACTIONS = frozenset(a.value for a in CustodyAction)
VALID_REVIEW_STATUSES = frozenset(s.value for s in ReviewStatus)
VALID_REVIEW_PRIORITIES = frozenset(p.value for p in ReviewPriority)

# Severity -> default review priority (Phase 13).
_SEVERITY_PRIORITY = {
    Severity.CRITICAL.value: ReviewPriority.P1.value,
    Severity.HIGH.value: ReviewPriority.P1.value,
    Severity.MEDIUM.value: ReviewPriority.P2.value,
    Severity.LOW.value: ReviewPriority.P3.value,
    Severity.INFORMATIONAL.value: ReviewPriority.P3.value,
}

MAX_NAME_LEN = 200
MAX_DETAIL_LEN = 2000
MAX_TEXT_LEN = 8000
MAX_META_JSON_LEN = 8000
DEFAULT_PAGE_LIMIT = 25
MAX_PAGE_LIMIT = 200

# Retention: 0 = keep indefinitely (backward-compatible default).
RETENTION_TIMELINE_DAYS = envutil.env_int("RT_RETENTION_TIMELINE_DAYS", 0)
RETENTION_EVIDENCE_DAYS = envutil.env_int("RT_RETENTION_EVIDENCE_DAYS", 0)


# ---------------- Result objects ----------------

@dataclass
class RoeDecision:
    """The composed RoE gate decision. `stage` names which layer failed,
    for an auditable, explainable denial."""
    allowed: bool
    reason: str
    stage: str = ""
    detail: str = ""
    engagement_id: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason, "stage": self.stage,
                "detail": self.detail, "engagement_id": self.engagement_id}


@dataclass
class RTResult:
    ok: bool
    reason: str = "OK"
    id: Optional[int] = None
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "reason": self.reason, "id": self.id, "detail": self.detail}


@dataclass
class IntegrityResult:
    ok: bool
    reason: str
    match: Optional[bool] = None
    stored_sha256: Optional[str] = None
    recalculated_sha256: Optional[str] = None
    verified_at: Optional[int] = None


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def redteam_db_init() -> None:
    """Create Phase 11 tables and indexes. Idempotent, additive; never
    touches another module's tables."""
    conn = _conn()

    conn.execute("""CREATE TABLE IF NOT EXISTS rt_engagements (
        engagement_id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        chat_id INTEGER NOT NULL,
        program_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        goal TEXT,
        status TEXT NOT NULL,
        roe_reference TEXT,
        roe_authorization_id INTEGER,
        window_start INTEGER,
        window_end INTEGER,
        expires_at INTEGER,
        created_by INTEGER NOT NULL,
        approved_by INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_engagements_chat "
                 "ON rt_engagements (chat_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_engagements_program "
                 "ON rt_engagements (program_id)")

    # Per-engagement authorized-operator allowlist.
    conn.execute("""CREATE TABLE IF NOT EXISTS rt_operators (
        engagement_id INTEGER NOT NULL,
        operator_id INTEGER NOT NULL,
        role TEXT NOT NULL DEFAULT 'OPERATOR',
        added_by INTEGER,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (engagement_id, operator_id)
    )""")

    conn.execute("""CREATE TABLE IF NOT EXISTS rt_targets (
        target_id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        value TEXT NOT NULL,
        normalized TEXT,
        category TEXT NOT NULL,
        authorization_status TEXT NOT NULL,
        testing_status TEXT NOT NULL DEFAULT 'NOT_STARTED',
        risk_score INTEGER NOT NULL DEFAULT 0,
        notes TEXT,
        discovered_by INTEGER,
        discovered_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_targets_engagement "
                 "ON rt_targets (engagement_id)")

    conn.execute("""CREATE TABLE IF NOT EXISTS rt_findings (
        finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        target_id INTEGER,
        title TEXT NOT NULL,
        classification TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        severity_rationale TEXT,
        description TEXT,
        origin_tool TEXT,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        reviewed_by INTEGER,
        reviewed_at INTEGER
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_findings_engagement "
                 "ON rt_findings (engagement_id, classification)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_findings_target "
                 "ON rt_findings (target_id)")

    # Evidence vault. content_sha256 is over the canonical hashed record
    # (see _HASHED_FIELDS); the row is append-effectively-immutable except
    # for the last_verify_* columns, which are excluded from the hash.
    conn.execute("""CREATE TABLE IF NOT EXISTS rt_evidence (
        evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        target_id INTEGER,
        finding_id INTEGER,
        kind TEXT NOT NULL,
        summary TEXT,
        raw_ref TEXT,
        raw_content TEXT,
        collected_by INTEGER,
        collected_at INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        last_verified_at INTEGER,
        last_verify_result TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_evidence_engagement "
                 "ON rt_evidence (engagement_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_evidence_finding "
                 "ON rt_evidence (finding_id)")

    # Append-only. No UPDATE/DELETE against this table anywhere.
    conn.execute("""CREATE TABLE IF NOT EXISTS rt_custody (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        evidence_id INTEGER,
        finding_id INTEGER,
        action TEXT NOT NULL,
        actor_id INTEGER,
        actor_kind TEXT NOT NULL DEFAULT 'operator',
        detail TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_custody_evidence "
                 "ON rt_custody (evidence_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_custody_engagement "
                 "ON rt_custody (engagement_id, created_at)")

    conn.execute("""CREATE TABLE IF NOT EXISTS rt_timeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        action TEXT NOT NULL,
        actor_id INTEGER,
        target_id INTEGER,
        finding_id INTEGER,
        evidence_id INTEGER,
        evidence_hash TEXT,
        detail TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_timeline_engagement "
                 "ON rt_timeline (engagement_id, created_at)")

    conn.execute("""CREATE TABLE IF NOT EXISTS rt_vectors (
        vector_id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        status TEXT NOT NULL,
        confidence TEXT NOT NULL,
        impact_score INTEGER NOT NULL DEFAULT 0,
        rationale TEXT,
        supporting_findings TEXT,
        review_decision TEXT,
        created_by INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_vectors_engagement "
                 "ON rt_vectors (engagement_id)")

    conn.execute("""CREATE TABLE IF NOT EXISTS rt_review_queue (
        item_id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        finding_id INTEGER,
        target_id INTEGER,
        priority TEXT NOT NULL,
        severity TEXT,
        status TEXT NOT NULL,
        summary TEXT,
        proposed_by TEXT,
        decided_by INTEGER,
        decided_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_review_engagement "
                 "ON rt_review_queue (engagement_id, status, priority)")

    # Defensive-control conflict log (Phase 10). Stores BOTH signals.
    conn.execute("""CREATE TABLE IF NOT EXISTS rt_defense_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        target_id INTEGER,
        red_action TEXT NOT NULL,
        red_time INTEGER,
        telemetry_result TEXT NOT NULL,
        telemetry_time INTEGER,
        outcome TEXT NOT NULL,
        detail TEXT,
        recorded_by INTEGER,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_defense_engagement "
                 "ON rt_defense_checks (engagement_id)")

    # AI analysis, stored DISTINCTLY from facts (Phase 19). Never read by
    # any decision path; purely advisory narrative attached to a subject.
    conn.execute("""CREATE TABLE IF NOT EXISTS rt_ai_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id INTEGER NOT NULL,
        subject_kind TEXT NOT NULL,
        subject_id INTEGER,
        model TEXT,
        content TEXT NOT NULL,
        created_by INTEGER,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_ai_engagement "
                 "ON rt_ai_analysis (engagement_id, subject_kind, subject_id)")

    conn.commit()
    conn.close()
    logger.info("REDTEAM DATABASE: OK")


# ---------------- Helpers ----------------

def _now(now: Optional[int] = None) -> int:
    return int(now) if now is not None else int(time.time())


def _clean(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text[:max_len] if text else None


def _limit(limit: Optional[int]) -> int:
    if limit is None:
        return DEFAULT_PAGE_LIMIT
    try:
        v = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_LIMIT
    return DEFAULT_PAGE_LIMIT if v <= 0 else min(v, MAX_PAGE_LIMIT)


# Obvious end-user PII patterns scrubbed from evidence text before it is
# stored (Phase 15 data minimization). Technical proof (headers, hosts,
# tool output) is kept; incidental personal data is redacted. This is a
# best-effort minimizer, not a guarantee — operators remain responsible
# for not collecting unnecessary PII.
_PII_PATTERNS = (
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{2,4}\)?[ -]?){2,4}\d{2,4}\b"), "[REDACTED_PHONE]"),
)


def scrub_pii(text: Optional[str]) -> Optional[str]:
    """Redact obvious end-user PII from free text before storage. Order
    matters: card/SSN before the looser phone pattern so a card number is
    not partly eaten by the phone rule."""
    if not text:
        return text
    out = str(text)
    for pattern, replacement in _PII_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


# ---------------- Phase 1/2: Engagements + RoE gate ----------------

_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")


def _gen_code(chat_id: int, seq_hint: int) -> str:
    """Human-readable engagement code SG-RT-XXXX. Derived, not random, so
    it is stable and collision-checked by the UNIQUE constraint."""
    return f"SG-RT-{seq_hint:04d}"


def create_engagement(chat_id: int, name: str, created_by: int, goal: str = "",
                      code: Optional[str] = None, now: Optional[int] = None) -> RTResult:
    """Open a new engagement in PENDING_APPROVAL.

    A backing scope_policy Program is created (in PAUSED status) to own
    the scope rules and the RoE authorization; the engagement stores its
    program_id and delegates every in-scope decision to it. No operation
    is possible until the engagement is authorized (authorize_engagement)
    AND at least one INCLUDE scope rule exists."""
    chat_id, created_by = int(chat_id), int(created_by)
    name = _clean(name, MAX_NAME_LEN)
    if not name:
        return RTResult(False, "NAME_REQUIRED")
    if code is not None:
        code = _clean(code, 64)
        if not code or not _CODE_RE.match(code):
            return RTResult(False, "INVALID_CODE", detail="use letters/digits/._- (2-64)")

    ts = _now(now)
    program_id = create_program(chat_id, f"[RT] {name}", created_by=created_by,
                                metadata="redteam_engagement")
    # Default code from the program id keeps it unique and stable.
    final_code = code or _gen_code(chat_id, program_id)

    conn = _conn()
    try:
        cur = conn.execute(
            "INSERT INTO rt_engagements (code, chat_id, program_id, name, goal, status, "
            "created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (final_code, chat_id, program_id, name, _clean(goal, MAX_DETAIL_LEN),
             EngagementStatus.PENDING_APPROVAL.value, created_by, ts, ts),
        )
        engagement_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return RTResult(False, "CODE_TAKEN", detail=f"code={final_code}")
    conn.close()

    # The engagement lead is an authorized operator by default.
    _add_operator_row(engagement_id, created_by, role="LEAD", added_by=created_by, now=ts)
    _timeline(engagement_id, TimelineKind.ADMINISTRATIVE_CHANGE, "ENGAGEMENT_CREATED",
              actor_id=created_by, detail=f"code={final_code}", now=ts)
    write_audit_log(chat_id, created_by, actor="user", action="RT_ENGAGEMENT_CREATED",
                    detail=f"engagement_id={engagement_id} code={final_code} "
                           f"program_id={program_id}")
    logger.info("RT ENGAGEMENT CREATED | id=%s code=%s program=%s",
                engagement_id, final_code, program_id)
    return RTResult(True, "OK", id=engagement_id, detail=final_code)


def get_engagement(engagement_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM rt_engagements WHERE engagement_id=?",
                       (int(engagement_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_engagement_by_code(code: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM rt_engagements WHERE code=?",
                       (_clean(code, 64),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_engagements(chat_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM rt_engagements WHERE chat_id=? ORDER BY engagement_id DESC LIMIT ?",
        (int(chat_id), _limit(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _add_operator_row(engagement_id: int, operator_id: int, role: str,
                      added_by: Optional[int], now: int) -> None:
    conn = _conn()
    conn.execute(
        "INSERT OR IGNORE INTO rt_operators (engagement_id, operator_id, role, added_by, "
        "added_at) VALUES (?, ?, ?, ?, ?)",
        (int(engagement_id), int(operator_id), role, added_by, now),
    )
    conn.commit()
    conn.close()


def add_operator(engagement_id: int, operator_id: int, actor_id: int,
                 role: str = "OPERATOR", now: Optional[int] = None) -> RTResult:
    """Add an authorized operator to an engagement. Only a member of the
    engagement (typically the lead) records this; the RoE gate then
    checks operator membership, so this list is a genuine allowlist."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    ts = _now(now)
    _add_operator_row(engagement_id, operator_id, "OPERATOR" if role != "LEAD" else "LEAD",
                      added_by=actor_id, now=ts)
    _timeline(engagement_id, TimelineKind.ADMINISTRATIVE_CHANGE, "OPERATOR_ADDED",
              actor_id=actor_id, detail=f"operator_id={operator_id} role={role}", now=ts)
    write_audit_log(engagement["chat_id"], actor_id, actor="user",
                    action="RT_OPERATOR_ADDED",
                    detail=f"engagement_id={engagement_id} operator_id={operator_id}")
    return RTResult(True, "OK", id=int(operator_id))


def list_operators(engagement_id: int) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM rt_operators WHERE engagement_id=? ORDER BY added_at",
        (int(engagement_id),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def is_authorized_operator(engagement_id: int, operator_id: int) -> bool:
    conn = _conn()
    row = conn.execute(
        "SELECT 1 FROM rt_operators WHERE engagement_id=? AND operator_id=?",
        (int(engagement_id), int(operator_id))).fetchone()
    conn.close()
    return row is not None


def add_scope(engagement_id: int, rule_type: str, target_type: str, pattern: str,
              actor_id: int, now: Optional[int] = None) -> RTResult:
    """Add an INCLUDE/EXCLUDE scope rule to the engagement's backing
    Program. Delegates entirely to scope_policy.add_scope_rule — this
    module never re-implements domain/IP/CIDR matching."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    rt = (rule_type or "").strip().upper()
    tt = (target_type or "").strip().upper()
    if rt not in VALID_RULE_TYPES:
        return RTResult(False, "INVALID_RULE_TYPE")
    if tt not in VALID_TARGET_TYPES:
        return RTResult(False, "INVALID_TARGET_TYPE")
    rule_id = add_scope_rule(engagement["program_id"], rt, tt, pattern, actor_user_id=actor_id)
    if rule_id is None:
        return RTResult(False, "INVALID_PATTERN", detail=f"pattern={pattern!r}")
    ts = _now(now)
    _timeline(engagement_id, TimelineKind.ADMINISTRATIVE_CHANGE, "SCOPE_RULE_ADDED",
              actor_id=actor_id, detail=f"{rt} {tt} {pattern}", now=ts)
    write_audit_log(engagement["chat_id"], actor_id, actor="user", action="RT_SCOPE_ADDED",
                    detail=f"engagement_id={engagement_id} rule_id={rule_id} {rt} {tt}")
    return RTResult(True, "OK", id=rule_id, detail=f"{rt} {tt} {pattern}")


def list_scope(engagement_id: int) -> List[dict]:
    engagement = get_engagement(engagement_id)
    if not engagement:
        return []
    return list_scope_rules(engagement["program_id"])


def authorize_engagement(engagement_id: int, approver_id: int, roe_reference: str,
                         window_end: Optional[int] = None, expires_at: Optional[int] = None,
                         window_start: Optional[int] = None, limited: bool = False,
                         now: Optional[int] = None) -> RTResult:
    """Record RoE sign-off and move the engagement to an operational
    status (AUTHORIZED, or LIMITED_SCOPE when `limited`).

    This is the human authorization action. It drives the backing
    scope_policy Program consistently so evaluate_target() will function:
      1. activate the Program,
      2. import + review an Authorization that references the RoE, so the
         Program has a reviewed, in-force authorization,
      3. flip the engagement status and record the window/expiry.

    A signed RoE reference is mandatory: without it there is no
    authorization basis and the call is refused."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    roe_reference = _clean(roe_reference, MAX_DETAIL_LEN)
    if not roe_reference:
        return RTResult(False, "ROE_REFERENCE_REQUIRED",
                        detail="a signed RoE/SOW reference is mandatory")
    if engagement["status"] in TERMINAL_STATUSES:
        return RTResult(False, "ENGAGEMENT_TERMINAL", detail=f"status={engagement['status']}")

    ts = _now(now)
    program_id = engagement["program_id"]

    # 1) activate the backing program (PAUSED -> ACTIVE). ARCHIVED can't
    #    happen for a live engagement's program; guard anyway.
    program = get_program(program_id)
    if program and program["status"] != ProgramStatus.ACTIVE.value:
        set_program_status(program_id, ProgramStatus.ACTIVE.value, approver_id)

    # 2) record the RoE as a reviewed scope_policy Authorization, unless
    #    one already exists for this engagement.
    auth_id = engagement["roe_authorization_id"]
    if not auth_id:
        auth_id = import_authorization(
            program_id, source_type="roe", actor_user_id=approver_id,
            source_reference=roe_reference, authorization_reference=roe_reference,
            effective_at=window_start, expires_at=expires_at)
        if auth_id is not None:
            review_authorization(auth_id, approve=True, reviewer_user_id=approver_id,
                                 notes="RoE sign-off via authorize_engagement")

    new_status = (EngagementStatus.LIMITED_SCOPE.value if limited
                  else EngagementStatus.AUTHORIZED.value)
    conn = _conn()
    conn.execute(
        "UPDATE rt_engagements SET status=?, roe_reference=?, roe_authorization_id=?, "
        "window_start=?, window_end=?, expires_at=?, approved_by=?, updated_at=? "
        "WHERE engagement_id=?",
        (new_status, roe_reference, auth_id, window_start, window_end, expires_at,
         int(approver_id), ts, int(engagement_id)),
    )
    conn.commit()
    conn.close()

    _timeline(engagement_id, TimelineKind.ADMINISTRATIVE_CHANGE, "ENGAGEMENT_AUTHORIZED",
              actor_id=approver_id, detail=f"status={new_status} roe={roe_reference}", now=ts)
    write_audit_log(engagement["chat_id"], approver_id, actor="user",
                    action="RT_ENGAGEMENT_AUTHORIZED",
                    detail=f"engagement_id={engagement_id} status={new_status} "
                           f"roe_authorization_id={auth_id}")
    return RTResult(True, "OK", id=int(engagement_id), detail=new_status)


def set_engagement_status(engagement_id: int, new_status: str, actor_id: int,
                          reason: str = "", now: Optional[int] = None) -> RTResult:
    """Transition engagement status along ENGAGEMENT_TRANSITIONS.
    TERMINATED/EXPIRED are terminal. Used for pause/resume and the
    kill-switch (see trigger_kill_switch)."""
    new_status = (new_status or "").strip().upper()
    if new_status not in {s.value for s in EngagementStatus}:
        return RTResult(False, "INVALID_STATUS")
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    current = engagement["status"]
    if new_status == current:
        return RTResult(False, "NO_CHANGE", detail=f"status={current}")
    if new_status not in ENGAGEMENT_TRANSITIONS.get(current, frozenset()):
        return RTResult(False, "INVALID_TRANSITION", detail=f"{current} -> {new_status}")

    ts = _now(now)
    conn = _conn()
    conn.execute("UPDATE rt_engagements SET status=?, updated_at=? WHERE engagement_id=?",
                 (new_status, ts, int(engagement_id)))
    conn.commit()
    conn.close()
    _timeline(engagement_id, TimelineKind.ADMINISTRATIVE_CHANGE, "ENGAGEMENT_STATUS_CHANGED",
              actor_id=actor_id, detail=f"{current} -> {new_status} {reason}".strip(), now=ts)
    write_audit_log(engagement["chat_id"], actor_id, actor="user",
                    action="RT_ENGAGEMENT_STATUS",
                    detail=f"engagement_id={engagement_id} {current} -> {new_status}")
    return RTResult(True, "OK", id=int(engagement_id), detail=f"{current} -> {new_status}")


def trigger_kill_switch(engagement_id: int, actor_id: int, reason: str = "",
                        now: Optional[int] = None) -> RTResult:
    """Emergency stop: force the engagement to TERMINATED from any
    non-terminal status. After this, the RoE gate denies everything for
    the engagement — no operation can proceed."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    if engagement["status"] in TERMINAL_STATUSES:
        return RTResult(False, "ALREADY_TERMINAL", detail=f"status={engagement['status']}")
    ts = _now(now)
    conn = _conn()
    conn.execute("UPDATE rt_engagements SET status=?, updated_at=? WHERE engagement_id=?",
                 (EngagementStatus.TERMINATED.value, ts, int(engagement_id)))
    conn.commit()
    conn.close()
    # Also revoke the backing authorization so evaluate_target denies too.
    if engagement["roe_authorization_id"]:
        try:
            revoke_authorization(engagement["roe_authorization_id"], actor_id)
        except Exception:
            logger.exception("RT KILL-SWITCH | revoke failed for engagement %s", engagement_id)
    _timeline(engagement_id, TimelineKind.ADMINISTRATIVE_CHANGE, "KILL_SWITCH",
              actor_id=actor_id, detail=_clean(reason, MAX_DETAIL_LEN) or "", now=ts)
    write_audit_log(engagement["chat_id"], actor_id, actor="user", action="RT_KILL_SWITCH",
                    detail=f"engagement_id={engagement_id} reason={_clean(reason, 200) or '-'}")
    logger.warning("RT KILL-SWITCH ENGAGED | engagement_id=%s by=%s", engagement_id, actor_id)
    return RTResult(True, "OK", id=int(engagement_id), detail="TERMINATED")


def check_roe(engagement_id: int, target: str, operator_id: int,
              now: Optional[int] = None) -> RoeDecision:
    """THE RoE GATE. Deny-by-default, fail-closed, composed in order:
    engagement exists -> operational status -> not kill-switched ->
    within window -> not expired -> operator authorized -> scope_policy
    ALLOW. No is_admin input; nothing here can be widened by chat-admin
    status. Performs no network activity."""
    ts = _now(now)
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RoeDecision(False, "ENGAGEMENT_NOT_FOUND", stage="ENGAGEMENT")

    eid = engagement["engagement_id"]
    status = engagement["status"]

    if status == EngagementStatus.TERMINATED.value:
        return RoeDecision(False, "ENGAGEMENT_TERMINATED", stage="KILL_SWITCH",
                           engagement_id=eid)
    # Expiry: an operational engagement past expires_at is treated EXPIRED.
    if engagement["expires_at"] and ts > engagement["expires_at"]:
        return RoeDecision(False, "ENGAGEMENT_EXPIRED", stage="WINDOW", engagement_id=eid)
    if status not in OPERATIONAL_STATUSES:
        return RoeDecision(False, f"ENGAGEMENT_{status}", stage="STATUS", engagement_id=eid)

    ws, we = engagement["window_start"], engagement["window_end"]
    if ws and ts < ws:
        return RoeDecision(False, "WINDOW_NOT_OPEN", stage="WINDOW", engagement_id=eid,
                           detail="testing window has not started")
    if we and ts > we:
        return RoeDecision(False, "WINDOW_CLOSED", stage="WINDOW", engagement_id=eid,
                           detail="testing window has ended")

    if not is_authorized_operator(eid, operator_id):
        return RoeDecision(False, "OPERATOR_NOT_AUTHORIZED", stage="OPERATOR",
                           engagement_id=eid,
                           detail="operator is not on the engagement allowlist")

    # Delegate the actual in-scope decision to scope_policy — reused, not
    # reimplemented. This also re-checks program-active + reviewed auth.
    decision = evaluate_target(engagement["program_id"], target)
    if not decision.allowed:
        return RoeDecision(False, decision.reason, stage="SCOPE", engagement_id=eid,
                           detail=decision.detail)

    return RoeDecision(True, "OK", stage="ALLOW", engagement_id=eid, detail=decision.detail)

# ---------------- Internal timeline / custody writers ----------------

def _timeline(engagement_id: int, kind, action: str, actor_id: Optional[int] = None,
              target_id: Optional[int] = None, finding_id: Optional[int] = None,
              evidence_id: Optional[int] = None, evidence_hash: Optional[str] = None,
              detail: str = "", now: Optional[int] = None) -> Optional[int]:
    value = kind.value if isinstance(kind, TimelineKind) else str(kind)
    if value not in VALID_TIMELINE_KINDS:
        return None
    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_timeline (engagement_id, kind, action, actor_id, target_id, "
        "finding_id, evidence_id, evidence_hash, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), value, _clean(action, 100) or "EVENT",
         int(actor_id) if actor_id is not None else None,
         target_id, finding_id, evidence_id, evidence_hash,
         _clean(detail, MAX_DETAIL_LEN), ts),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def add_custody(engagement_id: int, action, actor_id: Optional[int] = None,
                evidence_id: Optional[int] = None, finding_id: Optional[int] = None,
                actor_kind: str = "operator", detail: str = "",
                now: Optional[int] = None) -> Optional[int]:
    value = action.value if isinstance(action, CustodyAction) else str(action)
    if value not in VALID_CUSTODY_ACTIONS:
        return None
    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_custody (engagement_id, evidence_id, finding_id, action, actor_id, "
        "actor_kind, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), evidence_id, finding_id, value,
         int(actor_id) if actor_id is not None else None,
         "system" if actor_kind == "system" else "operator",
         _clean(detail, MAX_DETAIL_LEN), ts),
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def get_custody_trail(engagement_id: Optional[int] = None, evidence_id: Optional[int] = None,
                      finding_id: Optional[int] = None, limit: Optional[int] = None) -> List[dict]:
    """Oldest-first handling trail. Requires at least one scope filter so
    an unbounded cross-engagement dump is impossible."""
    if engagement_id is None and evidence_id is None and finding_id is None:
        return []
    sql = ["SELECT * FROM rt_custody WHERE 1=1"]
    params: List[Any] = []
    for col, val in (("engagement_id", engagement_id), ("evidence_id", evidence_id),
                     ("finding_id", finding_id)):
        if val is not None:
            sql.append(f"AND {col}=?")
            params.append(int(val))
    sql.append("ORDER BY created_at ASC, id ASC LIMIT ?")
    params.append(_limit(limit))
    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_timeline(engagement_id: int, limit: Optional[int] = None,
                 kind: Optional[str] = None) -> List[dict]:
    sql = ["SELECT * FROM rt_timeline WHERE engagement_id=?"]
    params: List[Any] = [int(engagement_id)]
    if kind is not None:
        if kind not in VALID_TIMELINE_KINDS:
            return []
        sql.append("AND kind=?")
        params.append(kind)
    sql.append("ORDER BY created_at ASC, id ASC LIMIT ?")
    params.append(_limit(limit))
    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Phase 3/7: Target registry ----------------

def register_target(engagement_id: int, value: str, category: str, operator_id: int,
                    notes: str = "", now: Optional[int] = None) -> RTResult:
    """Register an in-scope target/asset. GATED: the RoE gate must ALLOW
    the target value for this operator, so an out-of-scope or
    unauthorized asset can never be registered. The stored
    authorization_status reflects the gate outcome at registration time."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    category = (category or "").strip().upper()
    if category not in VALID_ASSET_CATEGORIES:
        return RTResult(False, "INVALID_CATEGORY",
                        detail="one of: " + ", ".join(sorted(VALID_ASSET_CATEGORIES)))
    value = _clean(value, MAX_NAME_LEN)
    if not value:
        return RTResult(False, "VALUE_REQUIRED")

    ts = _now(now)
    # A simulated threat vector is a modelling construct, not a real host,
    # so it is not run through the network-scope gate — but it still must
    # belong to an operational, operator-authorized engagement.
    if category == AssetCategory.SIMULATED_THREAT_VECTOR.value:
        if engagement["status"] not in OPERATIONAL_STATUSES:
            return RTResult(False, "ENGAGEMENT_NOT_OPERATIONAL",
                            detail=f"status={engagement['status']}")
        if not is_authorized_operator(engagement_id, operator_id):
            return RTResult(False, "OPERATOR_NOT_AUTHORIZED")
        normalized = None
        auth_status = "SIMULATED"
    else:
        decision = check_roe(engagement_id, value, operator_id, now=ts)
        if not decision.allowed:
            write_audit_log(engagement["chat_id"], operator_id, actor="system",
                            action="RT_TARGET_REGISTER_DENIED",
                            detail=f"engagement_id={engagement_id} value={value!r} "
                                   f"stage={decision.stage} reason={decision.reason}")
            return RTResult(False, decision.reason,
                            detail=f"stage={decision.stage} {decision.detail}".strip())
        nt = scope_policy.normalize_target(value)
        normalized = (nt.raw if nt and nt.target_type == TargetType.URL.value
                      else (nt.domain if nt else None)) if nt else None
        auth_status = "IN_SCOPE"

    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_targets (engagement_id, value, normalized, category, "
        "authorization_status, discovered_by, notes, discovered_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), value, normalized, category, auth_status, int(operator_id),
         _clean(notes, MAX_DETAIL_LEN), ts, ts),
    )
    target_id = cur.lastrowid
    conn.commit()
    conn.close()

    _timeline(engagement_id, TimelineKind.OPERATOR_ACTION, "TARGET_REGISTERED",
              actor_id=operator_id, target_id=target_id,
              detail=f"{category} {value}", now=ts)
    write_audit_log(engagement["chat_id"], operator_id, actor="user",
                    action="RT_TARGET_REGISTERED",
                    detail=f"engagement_id={engagement_id} target_id={target_id} "
                           f"category={category}")
    return RTResult(True, "OK", id=target_id, detail=auth_status)


def get_target(target_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM rt_targets WHERE target_id=?",
                       (int(target_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_targets(engagement_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM rt_targets WHERE engagement_id=? ORDER BY target_id LIMIT ?",
        (int(engagement_id), _limit(limit))).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_target_status(target_id: int, testing_status: str, actor_id: int,
                      risk_score: Optional[int] = None, now: Optional[int] = None) -> RTResult:
    target = get_target(target_id)
    if not target:
        return RTResult(False, "TARGET_NOT_FOUND")
    ts = _now(now)
    status = _clean(testing_status, 40) or target["testing_status"]
    score = target["risk_score"] if risk_score is None else max(0, min(100, int(risk_score)))
    conn = _conn()
    conn.execute("UPDATE rt_targets SET testing_status=?, risk_score=?, updated_at=? "
                 "WHERE target_id=?", (status, score, ts, int(target_id)))
    conn.commit()
    conn.close()
    _timeline(target["engagement_id"], TimelineKind.OPERATOR_ACTION, "TARGET_STATUS_CHANGED",
              actor_id=actor_id, target_id=int(target_id),
              detail=f"status={status} risk={score}", now=ts)
    return RTResult(True, "OK", id=int(target_id), detail=status)


# ---------------- Phase 9: explainable risk scoring ----------------

# Deterministic base scores; rationale is always stored alongside.
_SEVERITY_BASE = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20, "INFORMATIONAL": 5}
_CONFIDENCE_FACTOR = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.6}


def compute_risk_score(severity: str, confidence: str,
                       compensating_controls: bool = False) -> int:
    """Explainable 0-100 score = severity base × confidence factor, minus
    a fixed reduction when compensating controls are recorded. Callers
    store the rationale string next to the number, never the number
    alone."""
    base = _SEVERITY_BASE.get((severity or "").upper(), 5)
    factor = _CONFIDENCE_FACTOR.get((confidence or "").upper(), 0.6)
    score = base * factor
    if compensating_controls:
        score *= 0.7
    return max(0, min(100, int(round(score))))


# ---------------- Phase 5/6/14: Findings + classification ----------------

def create_finding(engagement_id: int, title: str, operator_id: int,
                   classification: str = FindingClass.LEAD.value,
                   severity: str = Severity.INFORMATIONAL.value,
                   confidence: str = Confidence.LOW.value,
                   target_id: Optional[int] = None, description: str = "",
                   origin_tool: str = "", severity_rationale: str = "",
                   now: Optional[int] = None) -> RTResult:
    """Log a finding. A NEW finding may be created as UNKNOWN / LEAD /
    EXPOSURE freely. It may NOT be created directly as VERIFIED_RISK:
    that classification is reachable only through reclassify_finding()
    with attached evidence and a human operator, which is the encoded
    "no auto-promotion to VERIFIED_RISK without proof + review" rule."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    title = _clean(title, MAX_NAME_LEN)
    if not title:
        return RTResult(False, "TITLE_REQUIRED")
    classification = (classification or "").strip().upper()
    severity = (severity or "").strip().upper()
    confidence = (confidence or "").strip().upper()
    if classification not in VALID_FINDING_CLASSES:
        return RTResult(False, "INVALID_CLASSIFICATION")
    if classification == FindingClass.VERIFIED_RISK.value:
        return RTResult(False, "VERIFIED_RISK_REQUIRES_REVIEW",
                        detail="create as LEAD/EXPOSURE, then /rtreview verify with evidence")
    if severity not in VALID_SEVERITIES:
        return RTResult(False, "INVALID_SEVERITY")
    if confidence not in VALID_CONFIDENCE:
        return RTResult(False, "INVALID_CONFIDENCE")
    if target_id is not None:
        t = get_target(target_id)
        if not t or t["engagement_id"] != engagement_id:
            return RTResult(False, "TARGET_NOT_IN_ENGAGEMENT")

    ts = _now(now)
    if not severity_rationale:
        severity_rationale = (f"auto: base severity {severity} × confidence {confidence} "
                              f"= score {compute_risk_score(severity, confidence)}")
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_findings (engagement_id, target_id, title, classification, severity, "
        "confidence, severity_rationale, description, origin_tool, created_by, created_at, "
        "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), target_id, title, classification, severity, confidence,
         _clean(severity_rationale, MAX_DETAIL_LEN), _clean(description, MAX_TEXT_LEN),
         _clean(origin_tool, 100), int(operator_id), ts, ts),
    )
    finding_id = cur.lastrowid
    conn.commit()
    conn.close()

    add_custody(engagement_id, CustodyAction.FINDING_CREATED, actor_id=operator_id,
                finding_id=finding_id, detail=f"class={classification} sev={severity}", now=ts)
    _timeline(engagement_id, TimelineKind.OPERATOR_ACTION, "FINDING_LOGGED",
              actor_id=operator_id, finding_id=finding_id, target_id=target_id,
              detail=f"{classification}/{severity}: {title}", now=ts)
    _enqueue_review(engagement_id, finding_id, target_id, severity, classification, title, ts)
    write_audit_log(engagement["chat_id"], operator_id, actor="user",
                    action="RT_FINDING_CREATED",
                    detail=f"engagement_id={engagement_id} finding_id={finding_id} "
                           f"class={classification} severity={severity}")
    return RTResult(True, "OK", id=finding_id, detail=classification)


def get_finding(finding_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM rt_findings WHERE finding_id=?",
                       (int(finding_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_findings(engagement_id: int, classification: Optional[str] = None,
                  limit: Optional[int] = None) -> List[dict]:
    sql = ["SELECT * FROM rt_findings WHERE engagement_id=?"]
    params: List[Any] = [int(engagement_id)]
    if classification is not None:
        c = classification.strip().upper()
        if c not in VALID_FINDING_CLASSES:
            return []
        sql.append("AND classification=?")
        params.append(c)
    sql.append("ORDER BY finding_id DESC LIMIT ?")
    params.append(_limit(limit))
    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def reclassify_finding(finding_id: int, new_classification: str, operator_id: int,
                       note: str = "", now: Optional[int] = None) -> RTResult:
    """Human reclassification. Promoting TO VERIFIED_RISK requires at
    least one evidence record attached to the finding — this is the
    hard gate that stops a LEAD/EXPOSURE (or any automated suggestion)
    from becoming a VERIFIED_RISK without proof. Demotions and moves
    among UNKNOWN/LEAD/EXPOSURE are always allowed during triage."""
    finding = get_finding(finding_id)
    if not finding:
        return RTResult(False, "FINDING_NOT_FOUND")
    new_classification = (new_classification or "").strip().upper()
    if new_classification not in VALID_FINDING_CLASSES:
        return RTResult(False, "INVALID_CLASSIFICATION")
    if new_classification == finding["classification"]:
        return RTResult(False, "NO_CHANGE", detail=f"class={new_classification}")

    ts = _now(now)
    if new_classification == FindingClass.VERIFIED_RISK.value:
        if count_finding_evidence(finding_id) <= 0:
            return RTResult(False, "EVIDENCE_REQUIRED",
                            detail="attach proof via /rtevidence before verifying")

    conn = _conn()
    conn.execute(
        "UPDATE rt_findings SET classification=?, reviewed_by=?, reviewed_at=?, updated_at=? "
        "WHERE finding_id=?",
        (new_classification, int(operator_id), ts, ts, int(finding_id)),
    )
    conn.commit()
    conn.close()

    detail = f"{finding['classification']} -> {new_classification}"
    add_custody(finding["engagement_id"], CustodyAction.FINDING_RECLASSIFIED,
                actor_id=operator_id, finding_id=int(finding_id),
                detail=f"{detail} {note}".strip(), now=ts)
    _timeline(finding["engagement_id"], TimelineKind.OPERATOR_ACTION, "FINDING_RECLASSIFIED",
              actor_id=operator_id, finding_id=int(finding_id), detail=detail, now=ts)
    write_audit_log(0, operator_id, actor="user", action="RT_FINDING_RECLASSIFIED",
                    detail=f"finding_id={finding_id} {detail}")
    return RTResult(True, "OK", id=int(finding_id), detail=detail)


# ---------------- Phase 4/16/17: Evidence vault + integrity ----------------

_HASHED_FIELDS = ("engagement_id", "target_id", "finding_id", "kind", "summary",
                  "raw_ref", "raw_content", "collected_by", "collected_at")
EVIDENCE_HASH_VERSION = "rt-evidence-v1"


def _canonical(record: Dict[str, Any]) -> str:
    payload = {"_v": EVIDENCE_HASH_VERSION}
    for name in _HASHED_FIELDS:
        payload[name] = record.get(name)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def _evidence_hash(record: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


def add_evidence(engagement_id: int, kind: str, operator_id: int, summary: str = "",
                 raw_content: Optional[str] = None, raw_ref: Optional[str] = None,
                 target_id: Optional[int] = None, finding_id: Optional[int] = None,
                 now: Optional[int] = None) -> RTResult:
    """Preserve an evidence artifact with a SHA-256 integrity hash.

    raw_content is PII-scrubbed before storage (data minimization); the
    scrubbed text is what is hashed, so verification is over exactly what
    is retained. Evidence is append-only in effect: nothing here rewrites
    a stored artifact's hashed fields."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    kind = (kind or "").strip().upper()
    if kind not in VALID_EVIDENCE_KINDS:
        return RTResult(False, "INVALID_EVIDENCE_KIND")
    if finding_id is not None:
        f = get_finding(finding_id)
        if not f or f["engagement_id"] != engagement_id:
            return RTResult(False, "FINDING_NOT_IN_ENGAGEMENT")
    if target_id is not None:
        t = get_target(target_id)
        if not t or t["engagement_id"] != engagement_id:
            return RTResult(False, "TARGET_NOT_IN_ENGAGEMENT")

    ts = _now(now)
    scrubbed = scrub_pii(_clean(raw_content, MAX_TEXT_LEN)) if raw_content is not None else None
    record = {
        "engagement_id": int(engagement_id),
        "target_id": target_id,
        "finding_id": finding_id,
        "kind": kind,
        "summary": _clean(summary, MAX_DETAIL_LEN),
        "raw_ref": _clean(raw_ref, MAX_DETAIL_LEN),
        "raw_content": scrubbed,
        "collected_by": int(operator_id),
        "collected_at": ts,
    }
    sha256_hex = _evidence_hash(record)

    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_evidence (engagement_id, target_id, finding_id, kind, summary, "
        "raw_ref, raw_content, collected_by, collected_at, sha256) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (record["engagement_id"], record["target_id"], record["finding_id"], record["kind"],
         record["summary"], record["raw_ref"], record["raw_content"], record["collected_by"],
         record["collected_at"], sha256_hex),
    )
    evidence_id = cur.lastrowid
    conn.commit()
    conn.close()

    add_custody(engagement_id, CustodyAction.EVIDENCE_CREATED, actor_id=operator_id,
                evidence_id=evidence_id, finding_id=finding_id,
                detail=f"kind={kind} sha256={sha256_hex[:16]}", now=ts)
    if finding_id is not None:
        add_custody(engagement_id, CustodyAction.EVIDENCE_LINKED, actor_id=operator_id,
                    evidence_id=evidence_id, finding_id=finding_id, now=ts)
    _timeline(engagement_id, TimelineKind.OPERATOR_ACTION, "EVIDENCE_COLLECTED",
              actor_id=operator_id, target_id=target_id, finding_id=finding_id,
              evidence_id=evidence_id, evidence_hash=sha256_hex,
              detail=f"kind={kind}", now=ts)
    write_audit_log(engagement["chat_id"], operator_id, actor="user",
                    action="RT_EVIDENCE_ADDED",
                    detail=f"engagement_id={engagement_id} evidence_id={evidence_id} "
                           f"kind={kind} sha256={sha256_hex}")
    return RTResult(True, "OK", id=evidence_id, detail=sha256_hex)


def get_evidence(evidence_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM rt_evidence WHERE evidence_id=?",
                       (int(evidence_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_evidence(engagement_id: Optional[int] = None, finding_id: Optional[int] = None,
                  limit: Optional[int] = None) -> List[dict]:
    if engagement_id is None and finding_id is None:
        return []
    sql = ["SELECT * FROM rt_evidence WHERE 1=1"]
    params: List[Any] = []
    if engagement_id is not None:
        sql.append("AND engagement_id=?")
        params.append(int(engagement_id))
    if finding_id is not None:
        sql.append("AND finding_id=?")
        params.append(int(finding_id))
    sql.append("ORDER BY evidence_id DESC LIMIT ?")
    params.append(_limit(limit))
    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_finding_evidence(finding_id: int) -> int:
    conn = _conn()
    row = conn.execute("SELECT COUNT(*) AS n FROM rt_evidence WHERE finding_id=?",
                       (int(finding_id),)).fetchone()
    conn.close()
    return row["n"] if row else 0


def verify_evidence(evidence_id: int, operator_id: Optional[int] = None,
                    now: Optional[int] = None) -> IntegrityResult:
    """Recompute the SHA-256 over the stored record and compare with the
    hash written at collection. MATCH => untampered; MISMATCH => the row
    changed after collection. Records the result in the row (excluded
    from the hash) and appends a custody event."""
    record = get_evidence(evidence_id)
    if not record:
        return IntegrityResult(False, "EVIDENCE_NOT_FOUND")
    stored = record.get("sha256")
    if not stored:
        return IntegrityResult(False, "NO_STORED_HASH")
    recalculated = _evidence_hash(record)
    match = recalculated == stored
    ts = _now(now)
    result_text = "VERIFIED" if match else "FAILED"

    conn = _conn()
    conn.execute("UPDATE rt_evidence SET last_verified_at=?, last_verify_result=? "
                 "WHERE evidence_id=?", (ts, result_text, int(evidence_id)))
    conn.commit()
    conn.close()

    add_custody(record["engagement_id"], CustodyAction.EVIDENCE_VERIFIED,
                actor_id=operator_id, evidence_id=int(evidence_id),
                finding_id=record.get("finding_id"),
                actor_kind="operator" if operator_id is not None else "system",
                detail=f"result={result_text}", now=ts)
    write_audit_log(record["engagement_id"], operator_id, actor="system",
                    action="RT_EVIDENCE_VERIFIED",
                    detail=f"evidence_id={evidence_id} result={result_text}")
    if not match:
        logger.warning("RT EVIDENCE INTEGRITY FAILED | evidence_id=%s", evidence_id)
    return IntegrityResult(True, "OK", match=match, stored_sha256=stored,
                           recalculated_sha256=recalculated, verified_at=ts)

# ---------------- Phase 8: attack-path / vector correlation ----------------

def create_vector(engagement_id: int, title: str, operator_id: int,
                  supporting_findings: Optional[List[int]] = None,
                  impact_score: int = 0, rationale: str = "",
                  now: Optional[int] = None) -> RTResult:
    """Record a POTENTIAL attack path. Conservative by construction: a
    new vector always starts UNVERIFIED with LOW confidence and can never
    be created as CONFIRMED. Escalation to CONFIRMED is a separate human
    review action (review_vector)."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    title = _clean(title, MAX_NAME_LEN)
    if not title:
        return RTResult(False, "TITLE_REQUIRED")
    ids = sorted({int(f) for f in (supporting_findings or [])})
    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_vectors (engagement_id, title, status, confidence, impact_score, "
        "rationale, supporting_findings, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), title, VectorStatus.UNVERIFIED.value, Confidence.LOW.value,
         max(0, min(100, int(impact_score))), _clean(rationale, MAX_DETAIL_LEN),
         json.dumps(ids), int(operator_id), ts, ts),
    )
    vector_id = cur.lastrowid
    conn.commit()
    conn.close()
    _timeline(engagement_id, TimelineKind.OPERATOR_ACTION, "VECTOR_LOGGED",
              actor_id=operator_id, detail=f"POTENTIAL: {title}", now=ts)
    write_audit_log(engagement["chat_id"], operator_id, actor="user",
                    action="RT_VECTOR_CREATED",
                    detail=f"engagement_id={engagement_id} vector_id={vector_id}")
    return RTResult(True, "OK", id=vector_id, detail="UNVERIFIED")


def get_vector(vector_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM rt_vectors WHERE vector_id=?",
                       (int(vector_id),)).fetchone()
    conn.close()
    if not row:
        return None
    item = dict(row)
    try:
        item["supporting_findings"] = json.loads(item.get("supporting_findings") or "[]")
    except (TypeError, ValueError):
        item["supporting_findings"] = []
    return item


def list_vectors(engagement_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM rt_vectors WHERE engagement_id=? ORDER BY vector_id DESC LIMIT ?",
        (int(engagement_id), _limit(limit))).fetchall()
    conn.close()
    out = []
    for r in rows:
        item = dict(r)
        try:
            item["supporting_findings"] = json.loads(item.get("supporting_findings") or "[]")
        except (TypeError, ValueError):
            item["supporting_findings"] = []
        out.append(item)
    return out


def review_vector(vector_id: int, status: str, operator_id: int, confidence: str = "",
                  decision: str = "", now: Optional[int] = None) -> RTResult:
    """Human review of a vector. CONFIRMED (i.e. an attack path treated as
    exploited/valid) is only reachable here, by a named operator — never
    automatically. Correlation can suggest a path; only review confirms
    it."""
    vector = get_vector(vector_id)
    if not vector:
        return RTResult(False, "VECTOR_NOT_FOUND")
    status = (status or "").strip().upper()
    if status not in VALID_VECTOR_STATUSES:
        return RTResult(False, "INVALID_STATUS")
    conf = (confidence or vector["confidence"]).strip().upper()
    if conf not in VALID_CONFIDENCE:
        return RTResult(False, "INVALID_CONFIDENCE")
    ts = _now(now)
    conn = _conn()
    conn.execute("UPDATE rt_vectors SET status=?, confidence=?, review_decision=?, "
                 "updated_at=? WHERE vector_id=?",
                 (status, conf, _clean(decision, MAX_DETAIL_LEN), ts, int(vector_id)))
    conn.commit()
    conn.close()
    _timeline(vector["engagement_id"], TimelineKind.OPERATOR_ACTION, "VECTOR_REVIEWED",
              actor_id=operator_id, detail=f"{vector['status']} -> {status} ({conf})", now=ts)
    write_audit_log(0, operator_id, actor="user", action="RT_VECTOR_REVIEWED",
                    detail=f"vector_id={vector_id} status={status} confidence={conf}")
    return RTResult(True, "OK", id=int(vector_id), detail=status)


# ---------------- Phase 13/14: review queue + human-in-the-loop ----------------

def _enqueue_review(engagement_id: int, finding_id: Optional[int], target_id: Optional[int],
                    severity: str, classification: str, summary: str, now: int) -> int:
    priority = _SEVERITY_PRIORITY.get(severity, ReviewPriority.P3.value)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_review_queue (engagement_id, finding_id, target_id, priority, "
        "severity, status, summary, proposed_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), finding_id, target_id, priority, severity,
         ReviewStatus.OPEN.value, _clean(summary, MAX_DETAIL_LEN),
         f"finding:{classification}", now, now),
    )
    item_id = cur.lastrowid
    conn.commit()
    conn.close()
    return item_id


def list_review_queue(engagement_id: int, status: Optional[str] = None,
                      limit: Optional[int] = None) -> List[dict]:
    sql = ["SELECT * FROM rt_review_queue WHERE engagement_id=?"]
    params: List[Any] = [int(engagement_id)]
    if status is not None:
        s = status.strip().upper()
        if s not in VALID_REVIEW_STATUSES:
            return []
        sql.append("AND status=?")
        params.append(s)
    # P1 before P2 before P3, newest within a priority.
    sql.append("ORDER BY priority ASC, item_id DESC LIMIT ?")
    params.append(_limit(limit))
    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def decide_review(item_id: int, decision: str, operator_id: int, note: str = "",
                  now: Optional[int] = None) -> RTResult:
    """Human decision on a queue item: IN_REVIEW / CONFIRMED / DISMISSED.

    If CONFIRMED and the item is a finding, the finding is promoted to
    VERIFIED_RISK — but only through reclassify_finding(), which enforces
    the evidence requirement. So confirming a finding with no evidence
    fails here too, keeping the one rule in one place."""
    decision = (decision or "").strip().upper()
    if decision not in VALID_REVIEW_STATUSES:
        return RTResult(False, "INVALID_DECISION")
    conn = _conn()
    row = conn.execute("SELECT * FROM rt_review_queue WHERE item_id=?",
                       (int(item_id),)).fetchone()
    item = dict(row) if row else None
    conn.close()
    if not item:
        return RTResult(False, "ITEM_NOT_FOUND")

    ts = _now(now)
    if decision == ReviewStatus.CONFIRMED.value and item["finding_id"]:
        promote = reclassify_finding(item["finding_id"], FindingClass.VERIFIED_RISK.value,
                                     operator_id, note=note, now=ts)
        if not promote.ok:
            return RTResult(False, promote.reason, detail=promote.detail)

    conn = _conn()
    conn.execute("UPDATE rt_review_queue SET status=?, decided_by=?, decided_at=?, "
                 "updated_at=? WHERE item_id=?",
                 (decision, int(operator_id), ts, ts, int(item_id)))
    conn.commit()
    conn.close()

    add_custody(item["engagement_id"], CustodyAction.REVIEW_DECISION, actor_id=operator_id,
                finding_id=item["finding_id"], detail=f"item={item_id} -> {decision} {note}".strip(),
                now=ts)
    _timeline(item["engagement_id"], TimelineKind.OPERATOR_ACTION, "REVIEW_DECISION",
              actor_id=operator_id, finding_id=item["finding_id"],
              detail=f"item {item_id}: {decision}", now=ts)
    write_audit_log(item["engagement_id"], operator_id, actor="user",
                    action="RT_REVIEW_DECISION",
                    detail=f"item_id={item_id} decision={decision}")
    return RTResult(True, "OK", id=int(item_id), detail=decision)


# ---------------- Phase 10: defensive-control conflict detection ----------------

def record_defense_check(engagement_id: int, red_action: str, telemetry_result: str,
                         operator_id: int, target_id: Optional[int] = None,
                         red_time: Optional[int] = None, telemetry_time: Optional[int] = None,
                         detail: str = "", now: Optional[int] = None) -> RTResult:
    """Record a red action and the client's defensive telemetry response
    for the same window, preserving BOTH signals. If the telemetry shows
    no/suppressed detection, the outcome is DEFENSIVE_GAP_DETECTED and it
    is routed to the review queue for Blue/Purple coordination.

    The gap is decided deterministically from telemetry_result keywords;
    the raw text of both signals is stored verbatim and never overwritten
    by that interpretation."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    red_action = _clean(red_action, MAX_DETAIL_LEN)
    telemetry_result = _clean(telemetry_result, MAX_DETAIL_LEN)
    if not red_action or not telemetry_result:
        return RTResult(False, "BOTH_SIGNALS_REQUIRED")
    ts = _now(now)
    lowered = telemetry_result.lower()
    detected = any(k in lowered for k in ("alert", "detected", "blocked", "triggered",
                                          "quarantined", "flagged"))
    suppressed = any(k in lowered for k in ("no alert", "not detected", "suppressed",
                                            "no detection", "missed", "none", "silent"))
    if suppressed or not detected:
        outcome = "DEFENSIVE_GAP_DETECTED"
    else:
        outcome = "DETECTION_CONFIRMED"

    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_defense_checks (engagement_id, target_id, red_action, red_time, "
        "telemetry_result, telemetry_time, outcome, detail, recorded_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), target_id, red_action, red_time, telemetry_result,
         telemetry_time, outcome, _clean(detail, MAX_DETAIL_LEN), int(operator_id), ts),
    )
    check_id = cur.lastrowid
    conn.commit()
    conn.close()

    if outcome == "DEFENSIVE_GAP_DETECTED":
        _enqueue_review(engagement_id, None, target_id, Severity.HIGH.value,
                        "DEFENSIVE_GAP", f"Defensive gap: {red_action}", ts)
    _timeline(engagement_id, TimelineKind.OBSERVED_HOST_EVENT, "DEFENSE_CHECK",
              actor_id=operator_id, target_id=target_id, detail=outcome, now=ts)
    write_audit_log(engagement["chat_id"], operator_id, actor="user",
                    action="RT_DEFENSE_CHECK",
                    detail=f"engagement_id={engagement_id} check_id={check_id} outcome={outcome}")
    return RTResult(True, "OK", id=check_id, detail=outcome)


def list_defense_checks(engagement_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM rt_defense_checks WHERE engagement_id=? ORDER BY id DESC LIMIT ?",
        (int(engagement_id), _limit(limit))).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Phase 19: AI analysis storage (labeled, never fact) ----------------

def add_ai_analysis(engagement_id: int, subject_kind: str, content: str,
                    subject_id: Optional[int] = None, model: str = "",
                    operator_id: Optional[int] = None, now: Optional[int] = None) -> RTResult:
    """Store an AI-generated narrative DISTINCTLY from technical facts.
    Nothing in this module ever reads rt_ai_analysis back into a decision;
    it is advisory text, always rendered under an explicit AI ANALYSIS
    label by the report layer."""
    engagement = get_engagement(engagement_id)
    if not engagement:
        return RTResult(False, "ENGAGEMENT_NOT_FOUND")
    content = _clean(content, MAX_TEXT_LEN)
    if not content:
        return RTResult(False, "CONTENT_REQUIRED")
    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO rt_ai_analysis (engagement_id, subject_kind, subject_id, model, "
        "content, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (int(engagement_id), _clean(subject_kind, 40) or "GENERAL", subject_id,
         _clean(model, 100), content, operator_id, ts),
    )
    ai_id = cur.lastrowid
    conn.commit()
    conn.close()
    write_audit_log(engagement["chat_id"], operator_id, actor="user",
                    action="RT_AI_ANALYSIS_ADDED",
                    detail=f"engagement_id={engagement_id} ai_id={ai_id} kind={subject_kind}")
    return RTResult(True, "OK", id=ai_id)


def list_ai_analysis(engagement_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM rt_ai_analysis WHERE engagement_id=? ORDER BY id DESC LIMIT ?",
        (int(engagement_id), _limit(limit))).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Phase 24: retention / cleanup ----------------

def retention_settings() -> Dict[str, int]:
    return {"timeline_days": RETENTION_TIMELINE_DAYS, "evidence_days": RETENTION_EVIDENCE_DAYS}


def purge_expired(engagement_id: Optional[int] = None, actor_id: Optional[int] = None,
                  now: Optional[int] = None) -> Dict[str, int]:
    """Delete records past their configured retention. 0 (default) keeps
    indefinitely and is skipped. Custody and audit are never purged here
    — the chain of custody must outlive operational logs. Returns
    per-table delete counts and writes one audit entry."""
    ts = _now(now)
    deleted: Dict[str, int] = {}
    plan = (("rt_timeline", "created_at", RETENTION_TIMELINE_DAYS),
            ("rt_evidence", "collected_at", RETENTION_EVIDENCE_DAYS))
    conn = _conn()
    try:
        for table, column, days in plan:
            if days <= 0:
                continue
            cutoff = ts - days * 86400
            sql = f"DELETE FROM {table} WHERE {column} < ?"
            params: List[Any] = [cutoff]
            if engagement_id is not None:
                sql += " AND engagement_id=?"
                params.append(int(engagement_id))
            cur = conn.execute(sql, params)
            deleted[table] = cur.rowcount or 0
        conn.commit()
    finally:
        conn.close()
    total = sum(deleted.values())
    if total:
        write_audit_log(0, actor_id, actor="system", action="RT_DATA_PURGED",
                        detail=", ".join(f"{k}={v}" for k, v in sorted(deleted.items()) if v))
    return deleted


# ---------------- Aggregate reads for reporting ----------------

def get_engagement_stats(engagement_id: int) -> dict:
    conn = _conn()
    by_class = {r["classification"]: r["n"] for r in conn.execute(
        "SELECT classification, COUNT(*) AS n FROM rt_findings WHERE engagement_id=? "
        "GROUP BY classification", (int(engagement_id),)).fetchall()}
    by_sev = {r["severity"]: r["n"] for r in conn.execute(
        "SELECT severity, COUNT(*) AS n FROM rt_findings WHERE engagement_id=? "
        "GROUP BY severity", (int(engagement_id),)).fetchall()}
    targets = conn.execute("SELECT COUNT(*) AS n FROM rt_targets WHERE engagement_id=?",
                           (int(engagement_id),)).fetchone()["n"]
    evidence = conn.execute("SELECT COUNT(*) AS n FROM rt_evidence WHERE engagement_id=?",
                            (int(engagement_id),)).fetchone()["n"]
    open_reviews = conn.execute(
        "SELECT COUNT(*) AS n FROM rt_review_queue WHERE engagement_id=? AND status=?",
        (int(engagement_id), ReviewStatus.OPEN.value)).fetchone()["n"]
    gaps = conn.execute(
        "SELECT COUNT(*) AS n FROM rt_defense_checks WHERE engagement_id=? AND outcome=?",
        (int(engagement_id), "DEFENSIVE_GAP_DETECTED")).fetchone()["n"]
    conn.close()
    return {"by_class": by_class, "by_severity": by_sev, "targets": targets,
            "evidence": evidence, "open_reviews": open_reviews, "defensive_gaps": gaps}
