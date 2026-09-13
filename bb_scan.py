"""
bb_scan.py — Phase 10: Authorized Scan Campaigns.

Builds directly on the existing Bug-Bounty stack, wiring three pieces
that already exist into one workflow:

    scope_policy.evaluate_target()   -- the authorization gate
    security_testing.run_security_check()  -- the actual passive checks
    findings.create_finding()        -- the record/triage layer

A "scan campaign" runs a fixed PROFILE of the passive checks that
security_testing.py already implements (headers / tls / cookies /
redirects / cors / technology) against ONE authorized target in one
request, aggregates the observations into a single prioritized,
persisted report with an explainable posture grade, and lets a human
promote any single observation into a real Finding (which then flows on
into Evidence / Case / bb_report exactly as a hand-created Finding does).

What this module deliberately is NOT (inherited verbatim from
security_testing.py, and it must never grow past them):
  - It opens no sockets itself. Every network operation goes through
    security_testing.run_security_check(), so that module's SSRF guard
    (_forbidden_ip_reason), port allow-list, redirect containment, rate
    limiting, timeouts and audit logging apply unchanged to every check
    a campaign runs. bb_scan adds orchestration and record-keeping only.
  - No new check types, no exploitation, no payloads, no crawling, no
    port/host discovery. A profile is a fixed subset of an existing
    fixed allow-list; an unknown profile or check name can never reach a
    code path.
  - No automatic Finding creation. A completed scan produces advisory
    observations only; promotion to a Finding is always an explicit,
    separately-authorized human action (promote_observation), and it
    re-runs evaluate_target() through create_finding() so a lapsed
    authorization blocks the promotion even when the scan itself ran
    earlier while in scope.
  - No `is_admin` input anywhere. Chat-admin status cannot widen what
    may be scanned; only Program -> ACTIVE -> Authorization -> INCLUDE
    scope (with no EXCLUDE) can, exactly as for a single /bbscan.

Authorization is decided up front by one read-only evaluate_target()
call (no network), and again inside every individual check. A denied
target performs zero network activity and is persisted as a DENIED scan
so the attempt is itself auditable.

Design constraints (matches scope_policy.py / findings.py / bb_case.py /
security_testing.py):
  - Standard library only, plus the modules above. No new dependency,
    no shell, no eval/exec, no background threads.
  - Reuses security.DB_PATH and security.write_audit_log(). No second
    database, no second audit system.
  - CREATE TABLE IF NOT EXISTS only; idempotent init; never a
    destructive migration.
  - Every query parameterized. Targets, codes and details are inert
    data: stored, length-capped, rendered as text, never interpreted.
"""

import time
import sqlite3
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from security import DB_PATH, write_audit_log
from scope_policy import evaluate_target, get_program
import security_testing
from security_testing import VALID_CHECK_TYPES, run_security_check
from findings import (
    create_finding, add_evidence, get_finding,
    VALID_SEVERITIES, Severity, EvidenceType,
)

logger = logging.getLogger(__name__)


# ---------------- Profiles (fixed allow-list, never user-arbitrary) ----------------
#
# A profile is looked up here and nowhere else; a value that is not a key
# never reaches any check. Each profile lists check types in the order
# they run (sequentially -- gentle on the target, and security_testing
# already caps its own concurrency). Every entry is intersected with
# security_testing.VALID_CHECK_TYPES at call time, so a check removed
# from that module can never be requested from here.

SCAN_PROFILES: Dict[str, tuple] = {
    # Fast triage: the three checks that most often surface a real
    # misconfiguration (missing security headers, weak cookies, TLS).
    "quick": ("headers", "cookies", "tls"),
    # Everything security_testing offers, in a stable order.
    "full": ("headers", "tls", "cookies", "redirects", "cors", "technology"),
}
DEFAULT_PROFILE = "full"
VALID_PROFILES = frozenset(SCAN_PROFILES)

# Outcome vocabularies (closed).
SCAN_COMPLETED = "COMPLETED"
SCAN_DENIED = "DENIED"
SCAN_FAILED = "FAILED"

CHECK_COMPLETED = "COMPLETED"
CHECK_FAILED = "FAILED"
CHECK_DENIED = "DENIED"

# security_testing only ever emits these three hints (it is passive).
SEVERITY_HINTS = ("MEDIUM", "LOW", "INFO")

# hint -> Finding severity when promoting. A human may override, but the
# default is a faithful, non-inflating map: a LOW observation does not
# silently become a HIGH Finding.
_HINT_TO_SEVERITY = {
    "INFO": Severity.INFO.value,
    "LOW": Severity.LOW.value,
    "MEDIUM": Severity.MEDIUM.value,
}

MAX_DETAIL_LEN = 1000
MAX_TITLE_LEN = 200
DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 100

# A scan is aggregate-advisory. This travels with every rendered report,
# mirroring security_testing's own "observations, not Findings" stance.
SCAN_DISCLAIMER = (
    "ผลสแกนเป็นข้อสังเกตจากการตรวจแบบ passive (ยิงคำขอปกติหนึ่งครั้งต่อการตรวจ) "
    "ยังไม่ใช่ Finding และเกรดเป็นเครื่องมือช่วยจัดลำดับการตรวจสอบ ไม่ใช่ข้อสรุปว่าปลอดภัย/ไม่ปลอดภัย "
    "ใช้ /scanpromote เพื่อยกข้อสังเกตขึ้นเป็น Finding จริงเมื่อผู้ดูแลพิจารณาแล้ว"
)


# ---------------- Result object ----------------

@dataclass
class ScanResult:
    ok: bool
    status: str                      # COMPLETED / DENIED / FAILED
    reason: str = "OK"
    scan_id: Optional[int] = None
    program_id: Optional[int] = None
    target: Optional[str] = None
    profile: Optional[str] = None
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "status": self.status, "reason": self.reason,
            "scan_id": self.scan_id, "program_id": self.program_id,
            "target": self.target, "profile": self.profile, "detail": self.detail,
        }


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def bb_scan_db_init() -> None:
    """Create Phase 10 tables only. Idempotent, additive; never touches
    another module's tables."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_scans (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        profile TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT,
        actor INTEGER NOT NULL,
        checks_requested INTEGER NOT NULL DEFAULT 0,
        checks_completed INTEGER NOT NULL DEFAULT 0,
        checks_failed INTEGER NOT NULL DEFAULT 0,
        checks_denied INTEGER NOT NULL DEFAULT 0,
        info_count INTEGER NOT NULL DEFAULT 0,
        low_count INTEGER NOT NULL DEFAULT 0,
        medium_count INTEGER NOT NULL DEFAULT 0,
        grade TEXT,
        started_at INTEGER NOT NULL,
        finished_at INTEGER
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_scans_program "
                 "ON bb_scans (program_id, started_at)")

    conn.execute("""CREATE TABLE IF NOT EXISTS bb_scan_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        check_type TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT,
        observation_count INTEGER NOT NULL DEFAULT 0
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_scan_checks_scan "
                 "ON bb_scan_checks (scan_id)")

    # 1-based `idx` per scan is the stable handle a human uses in
    # /scanpromote <scan_id> <idx>. promoted_finding_id is NULL until an
    # observation is promoted, and non-NULL blocks a second promotion of
    # the same observation.
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_scan_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        idx INTEGER NOT NULL,
        check_type TEXT NOT NULL,
        severity_hint TEXT NOT NULL,
        code TEXT NOT NULL,
        detail TEXT,
        promoted_finding_id INTEGER,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_scan_obs_scan "
                 "ON bb_scan_observations (scan_id, idx)")
    conn.commit()
    conn.close()
    logger.info("BB SCAN DATABASE: OK")


def _now(now: Optional[int] = None) -> int:
    return int(now) if now is not None else int(time.time())


def _clean(value: Optional[str], max_len: int) -> str:
    if value is None:
        return ""
    return str(value).strip()[:max_len]


def _limit(limit: Optional[int]) -> int:
    if limit is None:
        return DEFAULT_PAGE_LIMIT
    try:
        v = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_LIMIT
    return DEFAULT_PAGE_LIMIT if v <= 0 else min(v, MAX_PAGE_LIMIT)


def _grade(medium: int, low: int, info: int, completed: int) -> str:
    """Deterministic posture grade from observation counts.

    Explainable and deliberately coarse -- it orders a triage queue, it
    does not certify安全. security_testing is passive so it never emits
    HIGH/CRITICAL; the worst it can see is MEDIUM, so the scale tops out
    at C rather than pretending to a richer verdict than the data holds.
      A  = no observations (or purely informational)
      B  = only low-severity observations
      C  = at least one medium-severity observation
      N/A = no check completed (nothing was actually measured)
    """
    if completed <= 0:
        return "N/A"
    if medium > 0:
        return "C"
    if low > 0:
        return "B"
    return "A"


# ---------------- Orchestration ----------------

def _resolve_profile(profile: Optional[str]) -> Optional[List[str]]:
    """Profile name -> ordered list of check types that actually exist in
    security_testing right now. Returns None for an unknown profile."""
    name = (profile or DEFAULT_PROFILE).strip().lower()
    if name not in SCAN_PROFILES:
        return None
    return [c for c in SCAN_PROFILES[name] if c in VALID_CHECK_TYPES]


async def run_scan(program_id: int, target: str, actor: int,
                   profile: str = DEFAULT_PROFILE,
                   now: Optional[int] = None) -> Dict[str, Any]:
    """Run a scan campaign: a fixed profile of passive checks against one
    authorized target, aggregated and persisted.

    Fail-closed at every step. The single up-front evaluate_target()
    call is read-only and touches no network; if it denies, the scan is
    recorded as DENIED and NOT ONE check runs. When it allows, each check
    still re-enters run_security_check() and is independently gated,
    rate-limited and SSRF-guarded -- this function never weakens those.
    """
    ts = _now(now)
    ids = {"program_id": program_id if isinstance(program_id, int)
           and not isinstance(program_id, bool) else None,
           "target": None, "profile": None}

    if not isinstance(program_id, int) or isinstance(program_id, bool) or program_id <= 0:
        return ScanResult(False, SCAN_DENIED, "INVALID_PROGRAM_ID", **ids).as_dict()
    if not isinstance(actor, int) or isinstance(actor, bool) or actor <= 0:
        return ScanResult(False, SCAN_DENIED, "INVALID_ACTOR", **ids).as_dict()
    if not isinstance(target, str) or not target.strip():
        return ScanResult(False, SCAN_DENIED, "TARGET_INVALID", **ids).as_dict()

    check_types = _resolve_profile(profile)
    if check_types is None:
        return ScanResult(False, SCAN_DENIED, "UNKNOWN_PROFILE",
                          detail=f"profile={profile!r}", **ids).as_dict()
    if not check_types:
        return ScanResult(False, SCAN_FAILED, "NO_CHECKS_AVAILABLE", **ids).as_dict()
    profile_name = (profile or DEFAULT_PROFILE).strip().lower()
    ids["profile"] = profile_name

    program = get_program(program_id)
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, actor, actor="user", action="SCAN_REQUESTED",
                    detail=f"program_id={program_id} profile={profile_name}")

    # --- THE GATE (read-only, no network). Denied target scans nothing. ---
    decision = evaluate_target(program_id, target)
    if not decision.allowed:
        scan_id = _persist_scan(program_id, _clean(target, 512), profile_name, actor,
                                SCAN_DENIED, decision.reason, len(check_types),
                                0, 0, len(check_types), 0, 0, 0, "N/A", ts, ts)
        write_audit_log(chat_id, actor, actor="system", action="SCAN_DENIED",
                        detail=f"program_id={program_id} target={target!r} "
                               f"reason={decision.reason} scan_id={scan_id}")
        return ScanResult(False, SCAN_DENIED, decision.reason, scan_id=scan_id,
                          detail=decision.detail, **ids).as_dict()

    # --- authorized: run each check through the existing single-check path ---
    per_check: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    normalized_target = None
    counts = {"COMPLETED": 0, "FAILED": 0, "DENIED": 0}
    sev = {"INFO": 0, "LOW": 0, "MEDIUM": 0}

    for check_type in check_types:
        result = await run_security_check(program_id, target, check_type, actor)
        status = result.get("status", CHECK_FAILED)
        reason = result.get("reason", "")
        if normalized_target is None and result.get("target"):
            normalized_target = result["target"]
        obs = result.get("findings") or [] if status == CHECK_COMPLETED else []
        counts[status] = counts.get(status, 0) + 1
        for o in obs:
            hint = (o.get("severity_hint") or "INFO").upper()
            if hint not in sev:
                hint = "INFO"
            sev[hint] += 1
            observations.append({
                "check_type": check_type,
                "severity_hint": hint,
                "code": _clean(o.get("code"), 100) or "OBSERVATION",
                "detail": _clean(o.get("detail"), MAX_DETAIL_LEN),
            })
        per_check.append({"check_type": check_type, "status": status,
                          "reason": reason, "observation_count": len(obs)})

    finished = _now()
    stored_target = _clean(normalized_target or target, 512)

    # Every check denied for a target that passed the top gate means a
    # non-scope block hit each one -- rate limiting is the usual cause.
    # Surface it as FAILED (throttled/blocked), never COMPLETED.
    completed = counts.get(CHECK_COMPLETED, 0)
    overall = SCAN_COMPLETED if completed > 0 else SCAN_FAILED
    overall_reason = "OK" if completed > 0 else "NO_CHECK_COMPLETED"
    grade = _grade(sev["MEDIUM"], sev["LOW"], sev["INFO"], completed)

    scan_id = _persist_scan(
        program_id, stored_target, profile_name, actor, overall, overall_reason,
        len(check_types), completed, counts.get(CHECK_FAILED, 0),
        counts.get(CHECK_DENIED, 0), sev["INFO"], sev["LOW"], sev["MEDIUM"],
        grade, ts, finished,
    )
    _persist_checks(scan_id, per_check)
    _persist_observations(scan_id, observations, finished)

    write_audit_log(chat_id, actor, actor="system", action="SCAN_COMPLETED",
                    detail=f"program_id={program_id} target={stored_target} "
                           f"profile={profile_name} status={overall} grade={grade} "
                           f"observations={len(observations)} scan_id={scan_id}")
    return ScanResult(overall == SCAN_COMPLETED, overall, overall_reason,
                      scan_id=scan_id, target=stored_target,
                      program_id=program_id, profile=profile_name).as_dict()


def _persist_scan(program_id, target, profile, actor, status, reason,
                  requested, completed, failed, denied, info, low, medium,
                  grade, started_at, finished_at) -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO bb_scans (program_id, target, profile, status, reason, actor, "
        "checks_requested, checks_completed, checks_failed, checks_denied, "
        "info_count, low_count, medium_count, grade, started_at, finished_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (program_id, target, profile, status, reason, actor, requested, completed,
         failed, denied, info, low, medium, grade, started_at, finished_at),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def _persist_checks(scan_id: int, per_check: List[Dict[str, Any]]) -> None:
    if not per_check:
        return
    conn = _conn()
    conn.executemany(
        "INSERT INTO bb_scan_checks (scan_id, check_type, status, reason, "
        "observation_count) VALUES (?, ?, ?, ?, ?)",
        [(scan_id, c["check_type"], c["status"], c["reason"], c["observation_count"])
         for c in per_check],
    )
    conn.commit()
    conn.close()


def _persist_observations(scan_id: int, observations: List[Dict[str, Any]],
                          created_at: int) -> None:
    if not observations:
        return
    conn = _conn()
    conn.executemany(
        "INSERT INTO bb_scan_observations (scan_id, idx, check_type, severity_hint, "
        "code, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(scan_id, i, o["check_type"], o["severity_hint"], o["code"], o["detail"],
          created_at) for i, o in enumerate(observations, start=1)],
    )
    conn.commit()
    conn.close()


# ---------------- Reads ----------------

def get_scan(scan_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM bb_scans WHERE scan_id=?", (int(scan_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_scans(program_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_scans WHERE program_id=? ORDER BY scan_id DESC LIMIT ?",
        (int(program_id), _limit(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def list_scan_checks(scan_id: int) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_scan_checks WHERE scan_id=? ORDER BY id", (int(scan_id),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def list_observations(scan_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM bb_scan_observations WHERE scan_id=? ORDER BY idx LIMIT ?",
        (int(scan_id), _limit(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_observation(scan_id: int, idx: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM bb_scan_observations WHERE scan_id=? AND idx=?",
        (int(scan_id), int(idx)),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_scan_bundle(scan_id: int) -> Optional[dict]:
    scan = get_scan(scan_id)
    if not scan:
        return None
    return {
        "scan": scan,
        "checks": list_scan_checks(scan_id),
        "observations": list_observations(scan_id, limit=MAX_PAGE_LIMIT),
        "disclaimer": SCAN_DISCLAIMER,
    }


# ---------------- Bridge: observation -> Finding ----------------

@dataclass
class PromoteResult:
    ok: bool
    reason: str = "OK"
    finding_id: Optional[int] = None
    evidence_id: Optional[int] = None
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "reason": self.reason, "finding_id": self.finding_id,
                "evidence_id": self.evidence_id, "detail": self.detail}


def promote_observation(scan_id: int, idx: int, actor: int,
                        severity: Optional[str] = None,
                        title: Optional[str] = None) -> Dict[str, Any]:
    """Turn one stored scan observation into a real Finding.

    This is the bridge that closes security_testing.py's deliberate gap
    ("results are advisory; a human decides whether to report"). It is an
    explicit, separately-authorized action:

      - create_finding() re-runs evaluate_target(), so a promotion is
        refused if the Program/Authorization/scope no longer allows the
        target -- even though the scan ran earlier while it was in scope.
      - the observation's own detail is attached as TEXT evidence, so the
        Finding carries where it came from.
      - promoted_finding_id is stamped on the observation; a second
        promotion of the same observation is refused rather than quietly
        creating duplicate Findings.

    Severity defaults to a faithful map of the observation's hint and is
    never inflated automatically; a human may override it with any valid
    Finding severity.
    """
    if not isinstance(actor, int) or isinstance(actor, bool) or actor <= 0:
        return PromoteResult(False, "INVALID_ACTOR").as_dict()

    scan = get_scan(scan_id)
    if not scan:
        return PromoteResult(False, "SCAN_NOT_FOUND").as_dict()
    observation = get_observation(scan_id, idx)
    if not observation:
        return PromoteResult(False, "OBSERVATION_NOT_FOUND",
                             detail=f"scan_id={scan_id} idx={idx}").as_dict()
    if observation["promoted_finding_id"]:
        return PromoteResult(False, "ALREADY_PROMOTED",
                             finding_id=observation["promoted_finding_id"],
                             detail=f"finding_id={observation['promoted_finding_id']}").as_dict()

    if severity is not None:
        sev = str(severity).strip().upper()
        if sev not in VALID_SEVERITIES:
            return PromoteResult(False, "INVALID_SEVERITY", detail=f"severity={severity!r}").as_dict()
    else:
        sev = _HINT_TO_SEVERITY.get(observation["severity_hint"], Severity.INFO.value)

    resolved_title = _clean(title, MAX_TITLE_LEN) or \
        f"[{observation['code']}] {observation['check_type']} on {scan['target']}"
    description = (
        f"ยกจากผลสแกน #{scan_id} (โปรไฟล์ {scan['profile']})\n"
        f"การตรวจ: {observation['check_type']}\n"
        f"รหัสข้อสังเกต: {observation['code']} (hint {observation['severity_hint']})\n"
        f"รายละเอียด: {observation['detail'] or '-'}"
    )

    # create_finding() re-gates via evaluate_target(): promotion inherits
    # authorization from the CURRENT scope, not the scan's past scope.
    fr = create_finding(scan["program_id"], scan["target"], resolved_title,
                        created_by=actor, severity=sev, description=description)
    if not fr.ok:
        return PromoteResult(False, fr.reason, detail=fr.detail).as_dict()

    evidence_id = None
    ev = add_evidence(fr.finding_id, EvidenceType.TEXT.value, created_by=actor,
                     description=description)
    if ev.ok:
        evidence_id = ev.evidence_id

    conn = _conn()
    conn.execute(
        "UPDATE bb_scan_observations SET promoted_finding_id=? WHERE scan_id=? AND idx=?",
        (fr.finding_id, int(scan_id), int(idx)),
    )
    conn.commit()
    conn.close()

    program = get_program(scan["program_id"])
    chat_id = program["chat_id"] if program else 0
    write_audit_log(chat_id, actor, actor="user", action="SCAN_OBSERVATION_PROMOTED",
                    detail=f"scan_id={scan_id} idx={idx} finding_id={fr.finding_id} "
                           f"severity={sev}")
    logger.info("SCAN PROMOTE | scan_id=%s idx=%s -> finding_id=%s", scan_id, idx,
                fr.finding_id)
    return PromoteResult(True, "OK", finding_id=fr.finding_id,
                         evidence_id=evidence_id).as_dict()


# ---------------- Presentation ----------------

_REASON_TH = {
    "INVALID_PROGRAM_ID": "program_id ไม่ถูกต้อง",
    "INVALID_ACTOR": "ผู้ใช้ไม่ถูกต้อง",
    "TARGET_INVALID": "รูปแบบ target ไม่ถูกต้อง",
    "UNKNOWN_PROFILE": "ไม่รู้จักโปรไฟล์การสแกน (ใช้ได้: " + ", ".join(sorted(VALID_PROFILES)) + ")",
    "NO_CHECKS_AVAILABLE": "ไม่มีการตรวจที่ใช้ได้ในโปรไฟล์นี้",
    "NO_CHECK_COMPLETED": "ไม่มีการตรวจใดสำเร็จ (อาจติดโควตา/เครือข่าย)",
    "SCAN_NOT_FOUND": "ไม่พบผลสแกนนี้",
    "OBSERVATION_NOT_FOUND": "ไม่พบข้อสังเกตลำดับนี้ในผลสแกน",
    "ALREADY_PROMOTED": "ข้อสังเกตนี้ถูกยกเป็น Finding ไปแล้ว",
    "INVALID_SEVERITY": "ระดับความรุนแรงไม่ถูกต้อง (INFO/LOW/MEDIUM/HIGH/CRITICAL)",
}

_GRADE_TH = {
    "A": "A — ไม่พบข้อสังเกต หรือเป็นข้อมูลเชิงสารสนเทศเท่านั้น",
    "B": "B — พบข้อสังเกตระดับต่ำ",
    "C": "C — พบข้อสังเกตระดับกลาง ควรตรวจสอบ",
    "N/A": "N/A — ไม่มีการตรวจใดสำเร็จ (ยังไม่ได้วัดผล)",
}


def scan_deny_text(reason: str, detail: str = "") -> str:
    """Render a scan denial. Scope/authorization reasons come from
    evaluate_target(); reuse security_testing's Thai reason table for the
    network/rate-limit ones so the wording stays identical across the two
    scan commands."""
    base = _REASON_TH.get(reason)
    if base is None:
        base = security_testing._REASON_TH.get(reason, reason)
    text = "❌ " + base
    if detail:
        text += f" ({detail})"
    return text


def format_scan_result(result: Dict[str, Any]) -> str:
    """Short confirmation shown right after /scan runs."""
    if not result.get("ok"):
        return scan_deny_text(result.get("reason", "UNKNOWN"), result.get("detail", ""))
    scan = get_scan(result["scan_id"]) or {}
    grade = scan.get("grade", "N/A")
    lines = [
        f"🛰️ สแกนเสร็จ #{result['scan_id']} — {result['target']}",
        f"โปรไฟล์: {result['profile']} | เกรด: {_GRADE_TH.get(grade, grade)}",
        f"ตรวจสำเร็จ {scan.get('checks_completed', 0)}/{scan.get('checks_requested', 0)} "
        f"(ล้มเหลว {scan.get('checks_failed', 0)}, ถูกปฏิเสธ/จำกัด {scan.get('checks_denied', 0)})",
        f"ข้อสังเกต: MEDIUM {scan.get('medium_count', 0)} · "
        f"LOW {scan.get('low_count', 0)} · INFO {scan.get('info_count', 0)}",
        "",
        f"ดูรายละเอียด: /scanview {result['scan_id']}",
        "",
        f"ℹ️ {SCAN_DISCLAIMER}",
    ]
    return "\n".join(lines)


def format_scan_report(bundle: dict) -> str:
    """Full report for /scanview: coverage, every observation with its
    index (for /scanpromote), and promotion state."""
    scan = bundle["scan"]
    grade = scan.get("grade", "N/A")
    lines = [
        f"🛰️ รายงานการสแกน #{scan['scan_id']}",
        f"เป้าหมาย: {scan['target']}",
        f"Program: #{scan['program_id']} | โปรไฟล์: {scan['profile']} | สถานะ: {scan['status']}",
        f"เกรดภาพรวม: {_GRADE_TH.get(grade, grade)}",
    ]
    if scan["status"] == SCAN_DENIED:
        lines.append(f"เหตุผลที่ถูกปฏิเสธ: {scan_deny_text(scan.get('reason', ''))}")
        lines.append("")
        lines.append(f"ℹ️ {bundle.get('disclaimer', SCAN_DISCLAIMER)}")
        return "\n".join(lines)

    lines.append("")
    lines.append("ความครอบคลุมการตรวจ:")
    for c in bundle.get("checks") or []:
        mark = "✅" if c["status"] == CHECK_COMPLETED else (
            "⚠️" if c["status"] == CHECK_FAILED else "⛔")
        extra = f" ({c['reason']})" if c["status"] != CHECK_COMPLETED and c.get("reason") else ""
        lines.append(f"  {mark} {c['check_type']}: {c['status']}"
                     f"{extra} — {c['observation_count']} ข้อสังเกต")

    observations = bundle.get("observations") or []
    lines.append("")
    if not observations:
        lines.append("ไม่พบข้อสังเกตจากการตรวจที่สำเร็จ")
    else:
        lines.append(f"ข้อสังเกต {len(observations)} รายการ "
                     "(เลขลำดับใช้กับ /scanpromote):")
        for o in observations:
            detail = f" — {o['detail']}" if o["detail"] else ""
            promoted = (f"  ↳ ยกเป็น Finding #{o['promoted_finding_id']} แล้ว"
                        if o["promoted_finding_id"] else "")
            lines.append(f"  {o['idx']}. [{o['severity_hint']}] "
                         f"{o['check_type']}/{o['code']}{detail}")
            if promoted:
                lines.append(promoted)

    lines.append("")
    lines.append(f"ยกข้อสังเกตเป็น Finding: /scanpromote {scan['scan_id']} <ลำดับ> "
                 "[severity] [หัวข้อ]")
    lines.append(f"ℹ️ {bundle.get('disclaimer', SCAN_DISCLAIMER)}")
    return "\n".join(lines)


def format_scan_list(program_id: int, scans: List[dict]) -> str:
    lines = [f"🛰️ ประวัติการสแกน Program #{program_id}", ""]
    if not scans:
        lines.append("ยังไม่มีการสแกนใน Program นี้")
        return "\n".join(lines)
    for s in scans:
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(s["started_at"]))
        if s["status"] == SCAN_DENIED:
            lines.append(f"#{s['scan_id']} [{when}] {s['target']} — "
                         f"⛔ DENIED ({s.get('reason', '')})")
        else:
            lines.append(
                f"#{s['scan_id']} [{when}] {s['target']} — {s['status']} "
                f"เกรด {s.get('grade', 'N/A')} "
                f"(M{s.get('medium_count', 0)}/L{s.get('low_count', 0)}/"
                f"I{s.get('info_count', 0)})")
    lines.append("")
    lines.append("ดูรายละเอียด: /scanview <scan_id>")
    return "\n".join(lines)


def format_promote_result(result: Dict[str, Any]) -> str:
    if not result.get("ok"):
        reason = result.get("reason", "UNKNOWN")
        base = _REASON_TH.get(reason)
        if base is None:
            # promotion failures can be scope/authorization reasons from
            # create_finding()/evaluate_target(); reuse findings' wording
            # via security_testing's shared table where possible.
            base = security_testing._REASON_TH.get(reason, reason)
        text = "❌ ยกเป็น Finding ไม่สำเร็จ: " + base
        if result.get("detail"):
            text += f" ({result['detail']})"
        return text
    text = f"✅ ยกข้อสังเกตขึ้นเป็น Finding #{result['finding_id']} แล้ว (สถานะ OPEN)"
    if result.get("evidence_id"):
        text += f"\n📎 แนบรายละเอียดเป็น Evidence #{result['evidence_id']}"
    text += "\nจัดการต่อได้ด้วย /bbfinding show, /bbcase, /bbevidence"
    return text
