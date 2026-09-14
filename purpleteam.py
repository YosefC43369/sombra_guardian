"""
purpleteam.py — Phase 12: Purple Team Collaboration & Detection Validation.

The COLLABORATIVE layer that turns authorized red-team activity into
MEASURED blue-team detection coverage. It runs the purple-team
detect → tune → validate loop over threat-informed adversary emulation
(MITRE ATT&CK), records the defensive telemetry response for every
emulated action, computes detection coverage and mean-time-to-detect
(MTTD), and routes every detection gap to a tuning ticket for
Blue/Purple coordination.

WHAT THIS MODULE IS NOT, and must never become:
  - It launches NO attacks and runs NO detection engine. There is no
    exploit, payload, C2, scanner, credential attack, DoS or
    network-probing code anywhere in it. It opens no sockets. Emulation
    is EXECUTED by people (or by the existing security_testing.py engine
    through its own gate); this module only PLANS, RECORDS and MEASURES.
  - It never auto-validates a detection. A tuning ticket reaches
    VALIDATED only by a named human after a re-run actually detects the
    technique — enforced here as a state-machine gate. The module never
    concludes on its own that a control works.
  - It never widens authorization. An exercise can only RUN while its
    backing red-team engagement is operational (AUTHORIZED /
    LIMITED_SCOPE) and not kill-switched; the engagement's Rules of
    Engagement remain the single source of authorization truth.

AUTHORIZATION MODEL (reuse, not reinvention):
Every purple-team exercise is backed by a redteam.py Engagement. The
authorization decision is delegated ENTIRELY to that engagement:

    exercise exists and belongs to this chat
      -> backing engagement is operational (redteam.OPERATIONAL_STATUSES)
      -> engagement not kill-switched (not TERMINATED)
    == exercise may RUN.  Any failure => the exercise cannot start or
       record execution, fail-closed, deny-by-default.

There is NO `is_admin` input anywhere in this module's gates: the
Telegram-admin check lives in app.py and is necessary-but-not-sufficient,
exactly as in redteam.py / security_testing.py / bb_scan.py. Chat-admin
status can never widen an exercise's authorization by one byte.

Design constraints (matches redteam.py / scope_policy.py / findings.py /
bb_case.py / member_incident.py):
  - Standard library only, plus redteam + security. No new dependency, no
    shell, no eval/exec, no background threads, no network.
  - Reuses security.DB_PATH and security.write_audit_log(). No second
    database, no second audit system.
  - Reuses redteam.scrub_pii() for data minimization before storage.
  - CREATE TABLE IF NOT EXISTS only; idempotent init; never a
    destructive migration. Owns only pt_* tables; never touches another
    module's tables.
  - Every query parameterized. Technique IDs, telemetry, notes and
    detection logic are inert data: stored, length-capped, rendered as
    text, never interpreted, never used in an authorization decision.
  - The detection-round table is append-only: a re-run is a NEW row, so
    the before/after of a tuning cycle is preserved, never overwritten.
"""

import re
import time
import sqlite3
import logging
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any

import redteam as rtm
from redteam import scrub_pii
from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.purpleteam")


# ---------------- Enums / closed vocabularies ----------------

class ExerciseStatus(str, Enum):
    """Exercise lifecycle. Only RUNNING permits recording emulation
    execution; COMPLETED and CANCELLED are terminal."""
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class EmulationStatus(str, Enum):
    PLANNED = "PLANNED"
    EXECUTED = "EXECUTED"
    SKIPPED = "SKIPPED"


class DetectionOutcome(str, Enum):
    """What the defense actually did for one emulated action, best→worst.
    PREVENTED and DETECTED are wins; ALERTED is a partial (noisy/low-fidelity
    signal); LOGGED_ONLY means telemetry exists but nothing fired; MISSED
    means no signal at all."""
    PREVENTED = "PREVENTED"
    DETECTED = "DETECTED"
    ALERTED = "ALERTED"
    LOGGED_ONLY = "LOGGED_ONLY"
    MISSED = "MISSED"


class Coverage(str, Enum):
    """DeTT&CT-inspired per-technique coverage state, derived from the
    best detection outcome observed for that technique."""
    NONE = "NONE"
    TELEMETRY = "TELEMETRY"
    PARTIAL = "PARTIAL"
    DETECTION = "DETECTION"


class TuningStatus(str, Enum):
    """Detection-improvement ticket lifecycle. VALIDATED is reachable only
    by a human after a re-run detects the technique (no auto-validate)."""
    PROPOSED = "PROPOSED"
    IN_PROGRESS = "IN_PROGRESS"
    IMPLEMENTED = "IMPLEMENTED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"


class TimelineKind(str, Enum):
    ADMINISTRATIVE_CHANGE = "ADMINISTRATIVE_CHANGE"
    EMULATION_PLANNED = "EMULATION_PLANNED"
    DETECTION_RECORDED = "DETECTION_RECORDED"
    GAP_DETECTED = "GAP_DETECTED"
    TUNING_CHANGE = "TUNING_CHANGE"


VALID_EXERCISE_STATUSES = frozenset(s.value for s in ExerciseStatus)
VALID_EMULATION_STATUSES = frozenset(s.value for s in EmulationStatus)
VALID_DETECTION_OUTCOMES = frozenset(o.value for o in DetectionOutcome)
VALID_COVERAGE = frozenset(c.value for c in Coverage)
VALID_TUNING_STATUSES = frozenset(s.value for s in TuningStatus)

# A recorded outcome is a "detection gap" (needs tuning) when the defense
# did not produce an actionable detection.
GAP_OUTCOMES = frozenset({DetectionOutcome.LOGGED_ONLY.value,
                          DetectionOutcome.MISSED.value})

# Best→worst ranking used to reduce many rounds to one coverage state.
_OUTCOME_RANK = {
    DetectionOutcome.PREVENTED.value: 4,
    DetectionOutcome.DETECTED.value: 3,
    DetectionOutcome.ALERTED.value: 2,
    DetectionOutcome.LOGGED_ONLY.value: 1,
    DetectionOutcome.MISSED.value: 0,
}

# Best outcome for a technique -> its coverage state.
_OUTCOME_COVERAGE = {
    DetectionOutcome.PREVENTED.value: Coverage.DETECTION.value,
    DetectionOutcome.DETECTED.value: Coverage.DETECTION.value,
    DetectionOutcome.ALERTED.value: Coverage.PARTIAL.value,
    DetectionOutcome.LOGGED_ONLY.value: Coverage.TELEMETRY.value,
    DetectionOutcome.MISSED.value: Coverage.NONE.value,
}

# Allowed tuning transitions. REJECTED and VALIDATED are terminal.
_TUNING_TRANSITIONS = {
    TuningStatus.PROPOSED.value: frozenset({
        TuningStatus.IN_PROGRESS.value, TuningStatus.IMPLEMENTED.value,
        TuningStatus.REJECTED.value}),
    TuningStatus.IN_PROGRESS.value: frozenset({
        TuningStatus.IMPLEMENTED.value, TuningStatus.REJECTED.value}),
    TuningStatus.IMPLEMENTED.value: frozenset({
        TuningStatus.VALIDATED.value, TuningStatus.IN_PROGRESS.value,
        TuningStatus.REJECTED.value}),
    TuningStatus.VALIDATED.value: frozenset(),
    TuningStatus.REJECTED.value: frozenset(),
}

# MITRE ATT&CK technique id: Txxxx or Txxxx.xxx (sub-technique).
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")

MAX_NAME_LEN = 200
MAX_DETAIL_LEN = 2000
MAX_TEXT_LEN = 8000
DEFAULT_PAGE_LIMIT = 25
MAX_PAGE_LIMIT = 200


# ---------------- Result object ----------------

@dataclass
class PTResult:
    ok: bool
    reason: str = "OK"
    id: Optional[int] = None
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "reason": self.reason, "id": self.id, "detail": self.detail}


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def purpleteam_db_init() -> None:
    """Create Phase 12 tables and indexes. Idempotent, additive; never
    touches another module's tables."""
    conn = _conn()

    conn.execute("""CREATE TABLE IF NOT EXISTS pt_exercises (
        exercise_id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        chat_id INTEGER NOT NULL,
        engagement_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        objective TEXT,
        framework TEXT NOT NULL,
        status TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        started_at INTEGER,
        completed_at INTEGER
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_ex_chat "
                 "ON pt_exercises (chat_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_ex_eng "
                 "ON pt_exercises (engagement_id)")

    conn.execute("""CREATE TABLE IF NOT EXISTS pt_emulations (
        emulation_id INTEGER PRIMARY KEY AUTOINCREMENT,
        exercise_id INTEGER NOT NULL,
        technique_id TEXT NOT NULL,
        tactic TEXT,
        technique_name TEXT,
        description TEXT,
        target_ref TEXT,
        status TEXT NOT NULL,
        planned_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_emu_ex "
                 "ON pt_emulations (exercise_id)")

    # Append-only detection rounds. A re-run of the same emulation is a NEW
    # row so the before/after of a tuning cycle is preserved.
    conn.execute("""CREATE TABLE IF NOT EXISTS pt_detections (
        detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
        exercise_id INTEGER NOT NULL,
        emulation_id INTEGER NOT NULL,
        technique_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        data_source TEXT,
        telemetry TEXT,
        analyst_notes TEXT,
        executed_at INTEGER,
        detected_at INTEGER,
        detect_latency INTEGER,
        is_gap INTEGER NOT NULL DEFAULT 0,
        recorded_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_det_ex "
                 "ON pt_detections (exercise_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_det_emu "
                 "ON pt_detections (emulation_id)")

    conn.execute("""CREATE TABLE IF NOT EXISTS pt_tuning (
        tuning_id INTEGER PRIMARY KEY AUTOINCREMENT,
        exercise_id INTEGER NOT NULL,
        emulation_id INTEGER,
        technique_id TEXT,
        title TEXT NOT NULL,
        detection_logic TEXT,
        data_source TEXT,
        status TEXT NOT NULL,
        origin TEXT NOT NULL,
        proposed_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        decided_by INTEGER,
        decision_note TEXT,
        validated_by INTEGER,
        validated_at INTEGER,
        validated_detection_id INTEGER
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_tune_ex "
                 "ON pt_tuning (exercise_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_tune_status "
                 "ON pt_tuning (status)")

    # Append-only exercise activity log.
    conn.execute("""CREATE TABLE IF NOT EXISTS pt_timeline (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        exercise_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        action TEXT NOT NULL,
        actor_id INTEGER,
        detail TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pt_tl_ex "
                 "ON pt_timeline (exercise_id)")

    conn.commit()
    conn.close()


# ---------------- Small helpers ----------------

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


def normalize_technique(technique_id: Optional[str]) -> Optional[str]:
    """Uppercase and validate a MITRE ATT&CK technique id. Returns the
    canonical form (e.g. 'T1059.001') or None if it is not a technique
    id — the caller decides how to fail. Never raises."""
    if technique_id is None:
        return None
    t = str(technique_id).strip().upper()
    return t if _TECHNIQUE_RE.match(t) else None


def _gen_code(seq_hint: int) -> str:
    """Human-readable exercise code SG-PT-XXXX. Derived, not random, so it
    is stable and collision-checked by the UNIQUE constraint."""
    return f"SG-PT-{seq_hint:04d}"


def _timeline(exercise_id: int, kind, action: str, actor_id: Optional[int] = None,
              detail: str = "", now: Optional[int] = None) -> None:
    kind_value = kind.value if isinstance(kind, TimelineKind) else str(kind)
    conn = _conn()
    conn.execute(
        "INSERT INTO pt_timeline (exercise_id, kind, action, actor_id, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (int(exercise_id), kind_value, _clean(action, MAX_NAME_LEN), actor_id,
         _clean(detail, MAX_DETAIL_LEN), _now(now)))
    conn.commit()
    conn.close()


def get_timeline(exercise_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM pt_timeline WHERE exercise_id=? ORDER BY event_id DESC LIMIT ?",
        (int(exercise_id), _limit(limit))).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Phase 1: Exercises (backed by a red-team engagement) ----------------

def create_exercise(chat_id: int, engagement_id: int, name: str, created_by: int,
                    objective: str = "", framework: str = "MITRE_ATTACK",
                    now: Optional[int] = None) -> PTResult:
    """Create a purple-team exercise bound to an existing red-team
    engagement in the SAME chat. The engagement need not yet be
    operational to PLAN an exercise, but it must exist and belong here —
    authorization is re-checked at start_exercise()."""
    name = _clean(name, MAX_NAME_LEN)
    if not name:
        return PTResult(False, "NAME_REQUIRED")
    engagement = rtm.get_engagement(engagement_id)
    if not engagement:
        return PTResult(False, "ENGAGEMENT_NOT_FOUND")
    if engagement["chat_id"] != chat_id:
        return PTResult(False, "ENGAGEMENT_WRONG_CHAT")

    ts = _now(now)
    conn = _conn()
    seq = conn.execute("SELECT COUNT(*) AS n FROM pt_exercises").fetchone()["n"] + 1
    code = _gen_code(seq)
    cur = conn.execute(
        "INSERT INTO pt_exercises (code, chat_id, engagement_id, name, objective, "
        "framework, status, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (code, int(chat_id), int(engagement_id), name, _clean(objective, MAX_DETAIL_LEN),
         _clean(framework, MAX_NAME_LEN) or "MITRE_ATTACK",
         ExerciseStatus.PLANNED.value, int(created_by), ts, ts))
    exercise_id = cur.lastrowid
    conn.commit()
    conn.close()

    _timeline(exercise_id, TimelineKind.ADMINISTRATIVE_CHANGE, "EXERCISE_CREATED",
              actor_id=created_by, detail=f"engagement_id={engagement_id}", now=ts)
    write_audit_log(chat_id, created_by, actor="user", action="PT_EXERCISE_CREATED",
                    detail=f"exercise_id={exercise_id} code={code} "
                           f"engagement_id={engagement_id}")
    return PTResult(True, "OK", id=exercise_id, detail=code)


def get_exercise(exercise_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM pt_exercises WHERE exercise_id=?",
                       (int(exercise_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_exercise_by_code(code: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM pt_exercises WHERE code=?",
                       (str(code).strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_exercises(chat_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM pt_exercises WHERE chat_id=? ORDER BY exercise_id DESC LIMIT ?",
        (int(chat_id), _limit(limit))).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _engagement_operational(engagement_id: int, now: Optional[int] = None) -> PTResult:
    """Fail-closed check that the backing engagement authorizes activity:
    exists, not kill-switched, operational status, not expired. This is the
    RoE gate applied at the engagement level (target-level scope is the
    red-team side's concern via redteam.check_roe when a specific target
    is exercised)."""
    engagement = rtm.get_engagement(engagement_id)
    if not engagement:
        return PTResult(False, "ENGAGEMENT_NOT_FOUND")
    status = engagement["status"]
    if status == rtm.EngagementStatus.TERMINATED.value:
        return PTResult(False, "ENGAGEMENT_TERMINATED")
    ts = _now(now)
    if engagement["expires_at"] and ts > engagement["expires_at"]:
        return PTResult(False, "ENGAGEMENT_EXPIRED")
    if status not in rtm.OPERATIONAL_STATUSES:
        return PTResult(False, f"ENGAGEMENT_{status}")
    return PTResult(True, "OK")


def start_exercise(exercise_id: int, actor_id: int, now: Optional[int] = None) -> PTResult:
    """Move an exercise PLANNED -> RUNNING. Denies unless the backing
    engagement is operational and not kill-switched: emulation execution
    can only be recorded against a live, authorized engagement."""
    exercise = get_exercise(exercise_id)
    if not exercise:
        return PTResult(False, "EXERCISE_NOT_FOUND")
    if exercise["status"] != ExerciseStatus.PLANNED.value:
        return PTResult(False, f"NOT_PLANNED_{exercise['status']}")
    gate = _engagement_operational(exercise["engagement_id"], now=now)
    if not gate.ok:
        return PTResult(False, gate.reason, detail="backing engagement not operational")

    ts = _now(now)
    conn = _conn()
    conn.execute(
        "UPDATE pt_exercises SET status=?, started_at=?, updated_at=? WHERE exercise_id=?",
        (ExerciseStatus.RUNNING.value, ts, ts, int(exercise_id)))
    conn.commit()
    conn.close()
    _timeline(exercise_id, TimelineKind.ADMINISTRATIVE_CHANGE, "EXERCISE_STARTED",
              actor_id=actor_id, now=ts)
    write_audit_log(exercise["chat_id"], actor_id, actor="user",
                    action="PT_EXERCISE_STARTED", detail=f"exercise_id={exercise_id}")
    return PTResult(True, "OK", id=exercise_id, detail=ExerciseStatus.RUNNING.value)


def _terminal_transition(exercise_id: int, actor_id: int, new_status: str,
                         action: str, audit: str, reason: str = "",
                         now: Optional[int] = None) -> PTResult:
    exercise = get_exercise(exercise_id)
    if not exercise:
        return PTResult(False, "EXERCISE_NOT_FOUND")
    if exercise["status"] in (ExerciseStatus.COMPLETED.value,
                              ExerciseStatus.CANCELLED.value):
        return PTResult(False, f"ALREADY_{exercise['status']}")
    ts = _now(now)
    conn = _conn()
    conn.execute(
        "UPDATE pt_exercises SET status=?, completed_at=?, updated_at=? WHERE exercise_id=?",
        (new_status, ts, ts, int(exercise_id)))
    conn.commit()
    conn.close()
    _timeline(exercise_id, TimelineKind.ADMINISTRATIVE_CHANGE, action,
              actor_id=actor_id, detail=_clean(reason, MAX_DETAIL_LEN) or "", now=ts)
    write_audit_log(exercise["chat_id"], actor_id, actor="user", action=audit,
                    detail=f"exercise_id={exercise_id}")
    return PTResult(True, "OK", id=exercise_id, detail=new_status)


def complete_exercise(exercise_id: int, actor_id: int, now: Optional[int] = None) -> PTResult:
    return _terminal_transition(exercise_id, actor_id, ExerciseStatus.COMPLETED.value,
                                "EXERCISE_COMPLETED", "PT_EXERCISE_COMPLETED", now=now)


def cancel_exercise(exercise_id: int, actor_id: int, reason: str = "",
                    now: Optional[int] = None) -> PTResult:
    return _terminal_transition(exercise_id, actor_id, ExerciseStatus.CANCELLED.value,
                                "EXERCISE_CANCELLED", "PT_EXERCISE_CANCELLED",
                                reason=reason, now=now)


# ---------------- Phase 2: ATT&CK emulation planning ----------------

def add_emulation(exercise_id: int, technique_id: str, planned_by: int,
                  tactic: str = "", technique_name: str = "", description: str = "",
                  target_ref: str = "", now: Optional[int] = None) -> PTResult:
    """Plan one threat-informed adversary action, mapped to a MITRE ATT&CK
    technique. Allowed while the exercise is PLANNED or RUNNING (you can
    add coverage to an in-flight exercise); not on a terminal exercise."""
    exercise = get_exercise(exercise_id)
    if not exercise:
        return PTResult(False, "EXERCISE_NOT_FOUND")
    if exercise["status"] in (ExerciseStatus.COMPLETED.value,
                              ExerciseStatus.CANCELLED.value):
        return PTResult(False, f"EXERCISE_{exercise['status']}")
    technique = normalize_technique(technique_id)
    if not technique:
        return PTResult(False, "INVALID_TECHNIQUE_ID",
                        detail="expected MITRE ATT&CK id like T1059 or T1059.001")

    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO pt_emulations (exercise_id, technique_id, tactic, technique_name, "
        "description, target_ref, status, planned_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(exercise_id), technique, _clean(tactic, MAX_NAME_LEN),
         _clean(technique_name, MAX_NAME_LEN),
         scrub_pii(_clean(description, MAX_DETAIL_LEN)),
         _clean(target_ref, MAX_NAME_LEN), EmulationStatus.PLANNED.value,
         int(planned_by), ts, ts))
    emulation_id = cur.lastrowid
    conn.commit()
    conn.close()
    _timeline(exercise_id, TimelineKind.EMULATION_PLANNED, "EMULATION_ADDED",
              actor_id=planned_by, detail=f"{technique} emulation_id={emulation_id}", now=ts)
    write_audit_log(exercise["chat_id"], planned_by, actor="user",
                    action="PT_EMULATION_ADDED",
                    detail=f"exercise_id={exercise_id} emulation_id={emulation_id} "
                           f"technique={technique}")
    return PTResult(True, "OK", id=emulation_id, detail=technique)


def get_emulation(emulation_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM pt_emulations WHERE emulation_id=?",
                       (int(emulation_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_emulations(exercise_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM pt_emulations WHERE exercise_id=? ORDER BY emulation_id ASC LIMIT ?",
        (int(exercise_id), _limit(limit))).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Phase 3: the detect → tune → validate loop ----------------

def record_detection(exercise_id: int, emulation_id: int, outcome: str, recorded_by: int,
                     data_source: str = "", telemetry: str = "", analyst_notes: str = "",
                     executed_at: Optional[int] = None, detected_at: Optional[int] = None,
                     now: Optional[int] = None) -> PTResult:
    """Record the defensive telemetry response for one executed emulation
    — the DETECT step. The exercise must be RUNNING (which required an
    operational engagement). Both the raw telemetry and the analyst-set
    outcome are preserved; the gap decision is derived deterministically
    from the outcome, never from re-interpreting the text.

    When both executed_at and detected_at are present and the outcome is a
    real detection, detect_latency (seconds, MTTD input) is computed and
    stored. A gap outcome (LOGGED_ONLY / MISSED) auto-opens a PROPOSED
    tuning ticket for Blue/Purple coordination and is logged as a gap."""
    exercise = get_exercise(exercise_id)
    if not exercise:
        return PTResult(False, "EXERCISE_NOT_FOUND")
    if exercise["status"] != ExerciseStatus.RUNNING.value:
        return PTResult(False, f"EXERCISE_NOT_RUNNING_{exercise['status']}")
    emulation = get_emulation(emulation_id)
    if not emulation or emulation["exercise_id"] != exercise_id:
        return PTResult(False, "EMULATION_NOT_FOUND")
    out = str(outcome).strip().upper() if outcome else ""
    if out not in VALID_DETECTION_OUTCOMES:
        return PTResult(False, "INVALID_OUTCOME",
                        detail="one of " + ", ".join(sorted(VALID_DETECTION_OUTCOMES)))

    is_gap = 1 if out in GAP_OUTCOMES else 0
    latency = None
    detected = detected_at
    if out in (DetectionOutcome.MISSED.value,):
        # A miss has no detection instant; ignore any supplied detected_at.
        detected = None
    if executed_at is not None and detected is not None:
        latency = int(detected) - int(executed_at)
        if latency < 0:
            latency = None  # inconsistent clocks: store no latency rather than a lie

    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO pt_detections (exercise_id, emulation_id, technique_id, outcome, "
        "data_source, telemetry, analyst_notes, executed_at, detected_at, detect_latency, "
        "is_gap, recorded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(exercise_id), int(emulation_id), emulation["technique_id"], out,
         _clean(data_source, MAX_NAME_LEN),
         scrub_pii(_clean(telemetry, MAX_TEXT_LEN)),
         scrub_pii(_clean(analyst_notes, MAX_DETAIL_LEN)),
         executed_at, detected, latency, is_gap, int(recorded_by), ts))
    detection_id = cur.lastrowid
    conn.execute("UPDATE pt_emulations SET status=?, updated_at=? WHERE emulation_id=?",
                 (EmulationStatus.EXECUTED.value, ts, int(emulation_id)))
    conn.commit()
    conn.close()

    _timeline(exercise_id, TimelineKind.DETECTION_RECORDED, "DETECTION_RECORDED",
              actor_id=recorded_by,
              detail=f"{emulation['technique_id']} outcome={out}", now=ts)
    write_audit_log(exercise["chat_id"], recorded_by, actor="user",
                    action="PT_DETECTION_RECORDED",
                    detail=f"exercise_id={exercise_id} detection_id={detection_id} "
                           f"technique={emulation['technique_id']} outcome={out}")

    tuning_id = None
    if is_gap:
        tuning_id = _auto_open_tuning(exercise, emulation, out, recorded_by, ts)
        _timeline(exercise_id, TimelineKind.GAP_DETECTED, "DETECTION_GAP",
                  actor_id=recorded_by,
                  detail=f"{emulation['technique_id']} outcome={out} "
                         f"tuning_id={tuning_id}", now=ts)

    return PTResult(True, "OK", id=detection_id,
                    detail=("GAP" if is_gap else out))


def list_detections(exercise_id: int, emulation_id: Optional[int] = None,
                    limit: Optional[int] = None) -> List[dict]:
    sql = ["SELECT * FROM pt_detections WHERE exercise_id=?"]
    params: List[Any] = [int(exercise_id)]
    if emulation_id is not None:
        sql.append("AND emulation_id=?")
        params.append(int(emulation_id))
    sql.append("ORDER BY detection_id DESC LIMIT ?")
    params.append(_limit(limit))
    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Phase 4: tuning tickets (detection improvements) ----------------

def _auto_open_tuning(exercise: dict, emulation: dict, outcome: str,
                      actor_id: int, now: int) -> int:
    """A detection gap auto-opens a PROPOSED tuning ticket. This is the
    'tune' arm of the loop, created deterministically so no gap is lost;
    a human still owns the lifecycle from here."""
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO pt_tuning (exercise_id, emulation_id, technique_id, title, "
        "detection_logic, data_source, status, origin, proposed_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(exercise["exercise_id"]), int(emulation["emulation_id"]),
         emulation["technique_id"],
         f"Detection gap: {emulation['technique_id']} "
         f"({emulation.get('technique_name') or 'technique'})"[:MAX_NAME_LEN],
         None, None, TuningStatus.PROPOSED.value, f"AUTO:{outcome}",
         int(actor_id), now, now))
    tuning_id = cur.lastrowid
    conn.commit()
    conn.close()
    return tuning_id


def propose_tuning(exercise_id: int, title: str, proposed_by: int,
                   technique_id: str = "", emulation_id: Optional[int] = None,
                   detection_logic: str = "", data_source: str = "",
                   now: Optional[int] = None) -> PTResult:
    """Manually open a tuning ticket (a proposed detection rule / logic).
    detection_logic is stored verbatim as inert text (e.g. a Sigma-style
    description); it is never executed."""
    exercise = get_exercise(exercise_id)
    if not exercise:
        return PTResult(False, "EXERCISE_NOT_FOUND")
    title = _clean(title, MAX_NAME_LEN)
    if not title:
        return PTResult(False, "TITLE_REQUIRED")
    technique = normalize_technique(technique_id) if technique_id else None
    if technique_id and not technique:
        return PTResult(False, "INVALID_TECHNIQUE_ID")
    if emulation_id is not None:
        emulation = get_emulation(emulation_id)
        if not emulation or emulation["exercise_id"] != exercise_id:
            return PTResult(False, "EMULATION_NOT_FOUND")
        if not technique:
            technique = emulation["technique_id"]

    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO pt_tuning (exercise_id, emulation_id, technique_id, title, "
        "detection_logic, data_source, status, origin, proposed_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(exercise_id), emulation_id, technique, title,
         scrub_pii(_clean(detection_logic, MAX_TEXT_LEN)),
         _clean(data_source, MAX_NAME_LEN), TuningStatus.PROPOSED.value,
         "MANUAL", int(proposed_by), ts, ts))
    tuning_id = cur.lastrowid
    conn.commit()
    conn.close()
    _timeline(exercise_id, TimelineKind.TUNING_CHANGE, "TUNING_PROPOSED",
              actor_id=proposed_by, detail=f"tuning_id={tuning_id}", now=ts)
    write_audit_log(exercise["chat_id"], proposed_by, actor="user",
                    action="PT_TUNING_PROPOSED",
                    detail=f"exercise_id={exercise_id} tuning_id={tuning_id}")
    return PTResult(True, "OK", id=tuning_id, detail=TuningStatus.PROPOSED.value)


def get_tuning(tuning_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM pt_tuning WHERE tuning_id=?",
                       (int(tuning_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_tuning(exercise_id: int, status: Optional[str] = None,
                limit: Optional[int] = None) -> List[dict]:
    sql = ["SELECT * FROM pt_tuning WHERE exercise_id=?"]
    params: List[Any] = [int(exercise_id)]
    if status is not None:
        s = status.strip().upper()
        if s not in VALID_TUNING_STATUSES:
            return []
        sql.append("AND status=?")
        params.append(s)
    sql.append("ORDER BY tuning_id DESC LIMIT ?")
    params.append(_limit(limit))
    conn = _conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def set_tuning_status(tuning_id: int, new_status: str, actor_id: int, note: str = "",
                      now: Optional[int] = None) -> PTResult:
    """Advance a tuning ticket through PROPOSED -> IN_PROGRESS ->
    IMPLEMENTED -> (VALIDATED | REJECTED), enforcing the transition table.
    VALIDATED is intentionally NOT reachable here — a control is only
    proven by evidence, so use validate_tuning(), which requires a
    confirming detection round."""
    tuning = get_tuning(tuning_id)
    if not tuning:
        return PTResult(False, "TUNING_NOT_FOUND")
    target = str(new_status).strip().upper() if new_status else ""
    if target not in VALID_TUNING_STATUSES:
        return PTResult(False, "INVALID_STATUS")
    if target == TuningStatus.VALIDATED.value:
        return PTResult(False, "USE_VALIDATE_TUNING",
                        detail="VALIDATED requires a confirming detection round")
    allowed = _TUNING_TRANSITIONS.get(tuning["status"], frozenset())
    if target not in allowed:
        return PTResult(False, f"ILLEGAL_TRANSITION_{tuning['status']}_TO_{target}")

    ts = _now(now)
    conn = _conn()
    conn.execute(
        "UPDATE pt_tuning SET status=?, decided_by=?, decision_note=?, updated_at=? "
        "WHERE tuning_id=?",
        (target, int(actor_id), scrub_pii(_clean(note, MAX_DETAIL_LEN)), ts,
         int(tuning_id)))
    conn.commit()
    conn.close()
    _timeline(tuning["exercise_id"], TimelineKind.TUNING_CHANGE, f"TUNING_{target}",
              actor_id=actor_id, detail=f"tuning_id={tuning_id}", now=ts)
    exercise = get_exercise(tuning["exercise_id"])
    if exercise:
        write_audit_log(exercise["chat_id"], actor_id, actor="user",
                        action="PT_TUNING_STATUS",
                        detail=f"tuning_id={tuning_id} status={target}")
    return PTResult(True, "OK", id=tuning_id, detail=target)


def validate_tuning(tuning_id: int, detection_id: int, actor_id: int, note: str = "",
                    now: Optional[int] = None) -> PTResult:
    """The VALIDATE step: mark a tuning ticket VALIDATED, but ONLY when a
    named human points to a detection round that actually detected the
    technique (a win outcome) for the same exercise. No re-run that
    detects => no validation. The ticket must be IMPLEMENTED first."""
    tuning = get_tuning(tuning_id)
    if not tuning:
        return PTResult(False, "TUNING_NOT_FOUND")
    if tuning["status"] != TuningStatus.IMPLEMENTED.value:
        return PTResult(False, f"NOT_IMPLEMENTED_{tuning['status']}",
                        detail="a tuning ticket must be IMPLEMENTED before validation")

    conn = _conn()
    row = conn.execute("SELECT * FROM pt_detections WHERE detection_id=?",
                       (int(detection_id),)).fetchone()
    conn.close()
    detection = dict(row) if row else None
    if not detection or detection["exercise_id"] != tuning["exercise_id"]:
        return PTResult(False, "DETECTION_NOT_FOUND")
    if detection["outcome"] in GAP_OUTCOMES:
        return PTResult(False, "DETECTION_STILL_A_GAP",
                        detail="the cited round did not detect; cannot validate")
    # If the ticket names a technique, the confirming round must match it.
    if tuning["technique_id"] and detection["technique_id"] != tuning["technique_id"]:
        return PTResult(False, "TECHNIQUE_MISMATCH")

    ts = _now(now)
    conn = _conn()
    conn.execute(
        "UPDATE pt_tuning SET status=?, decided_by=?, decision_note=?, validated_by=?, "
        "validated_at=?, validated_detection_id=?, updated_at=? WHERE tuning_id=?",
        (TuningStatus.VALIDATED.value, int(actor_id),
         scrub_pii(_clean(note, MAX_DETAIL_LEN)), int(actor_id), ts,
         int(detection_id), ts, int(tuning_id)))
    conn.commit()
    conn.close()
    _timeline(tuning["exercise_id"], TimelineKind.TUNING_CHANGE, "TUNING_VALIDATED",
              actor_id=actor_id,
              detail=f"tuning_id={tuning_id} detection_id={detection_id}", now=ts)
    exercise = get_exercise(tuning["exercise_id"])
    if exercise:
        write_audit_log(exercise["chat_id"], actor_id, actor="user",
                        action="PT_TUNING_VALIDATED",
                        detail=f"tuning_id={tuning_id} detection_id={detection_id}")
    return PTResult(True, "OK", id=tuning_id, detail=TuningStatus.VALIDATED.value)


# ---------------- Phase 5: coverage + metrics (computed, never stored) ----------------

def get_technique_coverage(exercise_id: int) -> List[dict]:
    """Per-technique coverage across the whole exercise, DeTT&CT-style.
    The coverage state is derived from the BEST detection outcome observed
    for that technique over all rounds — computed live from the append-only
    detection log so it can never disagree with the records."""
    conn = _conn()
    emu_rows = conn.execute(
        "SELECT technique_id, tactic, technique_name FROM pt_emulations "
        "WHERE exercise_id=?", (int(exercise_id),)).fetchall()
    det_rows = conn.execute(
        "SELECT technique_id, outcome, detect_latency FROM pt_detections "
        "WHERE exercise_id=?", (int(exercise_id),)).fetchall()
    conn.close()

    meta: Dict[str, dict] = {}
    for r in emu_rows:
        m = meta.setdefault(r["technique_id"], {
            "technique_id": r["technique_id"], "tactic": r["tactic"] or "",
            "technique_name": r["technique_name"] or "", "rounds": 0,
            "best_outcome": None, "best_rank": -1, "latencies": []})
        if not m["tactic"] and r["tactic"]:
            m["tactic"] = r["tactic"]
        if not m["technique_name"] and r["technique_name"]:
            m["technique_name"] = r["technique_name"]

    for r in det_rows:
        m = meta.setdefault(r["technique_id"], {
            "technique_id": r["technique_id"], "tactic": "", "technique_name": "",
            "rounds": 0, "best_outcome": None, "best_rank": -1, "latencies": []})
        m["rounds"] += 1
        rank = _OUTCOME_RANK.get(r["outcome"], -1)
        if rank > m["best_rank"]:
            m["best_rank"] = rank
            m["best_outcome"] = r["outcome"]
        if r["detect_latency"] is not None:
            m["latencies"].append(int(r["detect_latency"]))

    out = []
    for m in meta.values():
        coverage = (_OUTCOME_COVERAGE.get(m["best_outcome"], Coverage.NONE.value)
                    if m["best_outcome"] else Coverage.NONE.value)
        out.append({
            "technique_id": m["technique_id"],
            "tactic": m["tactic"],
            "technique_name": m["technique_name"],
            "rounds": m["rounds"],
            "best_outcome": m["best_outcome"],
            "coverage": coverage,
            "mttd": (round(statistics.mean(m["latencies"]), 1)
                     if m["latencies"] else None),
        })
    out.sort(key=lambda x: (x["tactic"], x["technique_id"]))
    return out


def get_exercise_metrics(exercise_id: int) -> dict:
    """Roll up the loop into report-ready numbers: detection/prevention
    rates, gap counts, MTTD (mean & median over rounds that carry a
    latency), coverage-state histogram, and tuning-ticket status counts.
    All computed from the append-only records."""
    conn = _conn()
    det = conn.execute(
        "SELECT outcome, detect_latency, is_gap FROM pt_detections WHERE exercise_id=?",
        (int(exercise_id),)).fetchall()
    emu_total = conn.execute(
        "SELECT COUNT(*) AS n FROM pt_emulations WHERE exercise_id=?",
        (int(exercise_id),)).fetchone()["n"]
    emu_executed = conn.execute(
        "SELECT COUNT(*) AS n FROM pt_emulations WHERE exercise_id=? AND status=?",
        (int(exercise_id), EmulationStatus.EXECUTED.value)).fetchone()["n"]
    tuning_rows = conn.execute(
        "SELECT status, COUNT(*) AS n FROM pt_tuning WHERE exercise_id=? GROUP BY status",
        (int(exercise_id),)).fetchall()
    conn.close()

    rounds = len(det)
    by_outcome: Dict[str, int] = {}
    latencies: List[int] = []
    gaps = 0
    detected = 0
    prevented = 0
    for r in det:
        by_outcome[r["outcome"]] = by_outcome.get(r["outcome"], 0) + 1
        if r["is_gap"]:
            gaps += 1
        if r["outcome"] in (DetectionOutcome.DETECTED.value,
                            DetectionOutcome.PREVENTED.value,
                            DetectionOutcome.ALERTED.value):
            detected += 1
        if r["outcome"] == DetectionOutcome.PREVENTED.value:
            prevented += 1
        if r["detect_latency"] is not None:
            latencies.append(int(r["detect_latency"]))

    coverage = get_technique_coverage(exercise_id)
    cov_hist: Dict[str, int] = {c.value: 0 for c in Coverage}
    for c in coverage:
        cov_hist[c["coverage"]] = cov_hist.get(c["coverage"], 0) + 1
    techniques = len(coverage)
    covered = sum(1 for c in coverage if c["coverage"] == Coverage.DETECTION.value)

    return {
        "emulations_total": emu_total,
        "emulations_executed": emu_executed,
        "detection_rounds": rounds,
        "by_outcome": by_outcome,
        "gaps": gaps,
        "detection_rate": round(detected / rounds, 3) if rounds else 0.0,
        "prevention_rate": round(prevented / rounds, 3) if rounds else 0.0,
        "mttd_mean": round(statistics.mean(latencies), 1) if latencies else None,
        "mttd_median": round(statistics.median(latencies), 1) if latencies else None,
        "mttd_samples": len(latencies),
        "techniques": techniques,
        "techniques_with_detection": covered,
        "coverage_ratio": round(covered / techniques, 3) if techniques else 0.0,
        "coverage_histogram": cov_hist,
        "tuning_by_status": {r["status"]: r["n"] for r in tuning_rows},
    }
