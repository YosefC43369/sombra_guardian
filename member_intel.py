"""
member_intel.py — Phase 9: Member Identity, Activity & Risk Intelligence

Answers the observational half of the administrator's question:
"which Telegram account did this, when, and what did we actually see?"

Responsibilities (and only these):
  - Member Identity Registry        (Telegram user_id is the only stable key)
  - Identity History                (username / display-name snapshots)
  - Member Activity Timeline        (observable events, chronological)
  - Entry & Invite Tracking         (join/leave/rejoin + invite-link attribution
                                     ONLY when Telegram actually supplies it)
  - Explainable Risk Scoring        (triage signal, never a verdict)
  - Conservative Pattern Analysis   (correlation, never identity attribution)
  - Retention / purge               (privacy-by-design, configurable)

Deliberate non-responsibilities (these belong to modules that already own
them, and this module must never grow them):
  - Telegram I/O and moderation decisions -> app.py. This module never
    imports telegram, never deletes/warns/mutes, and never decides policy.
  - Cumulative security-event storage and the audit_log table ->
    security.py (record_event / write_audit_log). No second audit system
    and no second security_events table.
  - Message-content detection rules -> detection.py. This module consumes
    what detection.py already found; it re-implements no regex/threshold.
  - Incidents, the evidence vault and chain of custody ->
    member_incident.py, which imports this module (never the reverse).
  - Report rendering / export -> member_report.py, which owns no tables.

What Telegram's Bot API genuinely does NOT give a bot, and which this
module therefore never stores, infers, or pretends to have:
  - IP addresses. The Bot API never exposes a user's IP. Nothing here
    records, derives, or guesses one.
  - Phone numbers, email addresses, device identifiers, app/OS version,
    session or login metadata, auth tokens, cookies.
  - The full member list of a group, or a member's other groups.
  - Real-world identity of any kind.
  - Join events that happened before the bot was present, messages sent
    before the bot joined, or activity in chats the bot is not in.
  - Invite-link attribution for every join. `ChatMemberUpdated.invite_link`
    is populated only in some cases (see observe_membership_change); when
    it is absent the record says UNAVAILABLE rather than guessing.
Every read path distinguishes observed fact from absent data, and
member_report.py renders that distinction as a mandatory section.

Design constraints (matches security.py / detection.py / findings.py):
  - Standard library only (sqlite3, time, json, hashlib, re, dataclasses,
    enum). No network/API calls, no LLM calls, no background threads.
  - CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS only.
    Idempotent init, never a destructive migration, never touches another
    module's tables.
  - Every query parameterized. No SQL is ever built from user input.
  - Usernames, display names and message text are untrusted free text:
    stored as inert data, length-capped, never parsed as instructions,
    never fed into an authorization decision, and never executed.
  - Write paths called from message handlers do a small, bounded number
    of local SQLite writes and return (Render Background Worker friendly).
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

logger = logging.getLogger("modbot.member_intel")


# ---------------- Enums / Constants ----------------

class MembershipStatus(str, Enum):
    """Mirrors telegram.constants.ChatMemberStatus values, plus UNKNOWN for
    "the bot has seen this account but never observed a membership event".
    Kept as plain strings so this module never imports python-telegram-bot."""
    CREATOR = "CREATOR"
    ADMINISTRATOR = "ADMINISTRATOR"
    MEMBER = "MEMBER"
    RESTRICTED = "RESTRICTED"
    LEFT = "LEFT"
    BANNED = "BANNED"
    UNKNOWN = "UNKNOWN"


class IdentityField(str, Enum):
    USERNAME = "username"
    DISPLAY_NAME = "display_name"


class TimelineEvent(str, Enum):
    """Observable events only. Nothing here is inferred: each value is
    written either from a Telegram update the bot received or from an
    action the bot itself performed."""
    JOINED = "JOINED"
    LEFT = "LEFT"
    REJOINED = "REJOINED"
    FIRST_MESSAGE = "FIRST_MESSAGE"
    SUSPICIOUS_MESSAGE = "SUSPICIOUS_MESSAGE"
    WARNING_ISSUED = "WARNING_ISSUED"
    MESSAGE_REMOVED = "MESSAGE_REMOVED"
    RESTRICTED = "RESTRICTED"
    UNRESTRICTED = "UNRESTRICTED"
    BANNED = "BANNED"
    UNBANNED = "UNBANNED"
    PROMOTED = "PROMOTED"
    DEMOTED = "DEMOTED"
    IDENTITY_CHANGED = "IDENTITY_CHANGED"
    EVIDENCE_CAPTURED = "EVIDENCE_CAPTURED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    INCIDENT_RESOLVED = "INCIDENT_RESOLVED"


class JoinKind(str, Enum):
    JOINED = "JOINED"
    LEFT = "LEFT"
    REJOINED = "REJOINED"


VALID_TIMELINE_EVENTS = frozenset(e.value for e in TimelineEvent)
VALID_MEMBERSHIP_STATUSES = frozenset(s.value for s in MembershipStatus)
VALID_IDENTITY_FIELDS = frozenset(f.value for f in IdentityField)

# Marker used everywhere a value is genuinely not obtainable from the Bot
# API, so a report can say "unavailable" instead of rendering an empty
# string that reads like "nothing happened".
UNAVAILABLE = "UNAVAILABLE"

# Length caps for untrusted free text. Telegram's own limits are smaller
# than these for usernames/names; the caps exist so a hostile or buggy
# update can never write an unbounded row.
MAX_USERNAME_LEN = 64
MAX_DISPLAY_NAME_LEN = 256
MAX_DETAIL_LEN = 1024
MAX_META_JSON_LEN = 4096

# Bound every list/report read so one command can never load a whole table.
DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 200


class _Unset:
    """Sentinel for "the caller did not supply this field".

    Necessary because None is itself an observation: Telegram's User
    .username is None for an account that has no username, and recording
    that is the only way "username removed" can ever be a fact. If None
    also meant "not supplied", any caller that omitted the argument would
    silently write a fabricated removal event -- exactly the kind of
    invented history this module must never contain."""
    __slots__ = ()

    def __repr__(self):
        return "<unset>"


UNSET = _Unset()


# ---------------- Risk engine configuration ----------------
#
# The risk score is an administrative TRIAGE aid computed from events the
# bot observed. It is not proof of anything, it is not a statement about
# who a person is, and it never asserts criminality. Every point in the
# score carries the reason that produced it (see RiskReason), so an
# administrator can audit and disagree with it.
#
# security.py already keeps a single cumulative, never-decaying counter
# per (chat, user). That number cannot answer "why?" or "lately?", so it
# is reported here as an observed fact alongside this module's separate,
# windowed, itemised score. This module never writes to user_behavior.

RISK_WINDOW_SECONDS = envutil.env_int("MEMBER_RISK_WINDOW_SECONDS", 7 * 24 * 3600)
RISK_MEDIUM_MIN = envutil.env_int("MEMBER_RISK_MEDIUM_MIN", 30)
RISK_HIGH_MIN = envutil.env_int("MEMBER_RISK_HIGH_MIN", 70)
RISK_SCORE_MAX = 100

# Per-signal weight and cap. `cap` limits how much one signal type can
# contribute, so twenty deleted messages cannot drown out the fact that a
# confirmed incident exists.
@dataclass(frozen=True)
class RiskSignalSpec:
    code: str
    label: str
    weight: int
    cap: int


# Keyed by the security_events.event_type values security.py writes.
RISK_SIGNALS: Dict[str, RiskSignalSpec] = {
    "SPAM": RiskSignalSpec("SPAM", "สแปม/ส่งข้อความรัว", 8, 32),
    "FORBIDDEN_WORD": RiskSignalSpec("FORBIDDEN_WORD", "ใช้คำต้องห้าม", 5, 20),
    "BLOCKED_LINK": RiskSignalSpec("BLOCKED_LINK", "ลิงก์ต้องห้าม/ลิงก์น่าสงสัย", 10, 40),
    "MENTION_SPAM": RiskSignalSpec("MENTION_SPAM", "แท็กสมาชิกจำนวนมาก", 8, 24),
    "WARNING": RiskSignalSpec("WARNING", "ถูกเตือนโดยระบบ/ผู้ดูแล", 6, 30),
    "MUTE": RiskSignalSpec("MUTE", "ถูกปิดเสียง", 15, 30),
    "MESSAGE_DELETED": RiskSignalSpec("MESSAGE_DELETED", "ข้อความถูกลบ", 3, 15),
    "AI_FLAGGED_SPAM": RiskSignalSpec("AI_FLAGGED_SPAM", "AI ประเมินว่าเป็นสแปม", 8, 24),
    "DUPLICATE_MESSAGE": RiskSignalSpec("DUPLICATE_MESSAGE", "ส่งข้อความซ้ำ", 5, 20),
}

# Timeline-derived signals. Kept separate because these come from
# administrative outcomes, not from the detection engine.
RISK_TIMELINE_SIGNALS: Dict[str, RiskSignalSpec] = {
    TimelineEvent.RESTRICTED.value: RiskSignalSpec(
        "RESTRICTED", "ถูกจำกัดสิทธิ์", 12, 24),
    TimelineEvent.BANNED.value: RiskSignalSpec(
        "BANNED", "ถูกแบน", 25, 25),
}

# A CONFIRMED incident is the single strongest signal, because unlike
# everything above it required a human administrator to agree.
RISK_CONFIRMED_INCIDENT = RiskSignalSpec(
    "CONFIRMED_INCIDENT", "มีเหตุการณ์ที่ผู้ดูแลยืนยันแล้ว", 30, 60)


def risk_level(score: int) -> str:
    """LOW / MEDIUM / HIGH by configurable thresholds. Deliberately the
    same vocabulary security.py uses, so admins see one scale — but the
    boundaries are independently configurable because this score is
    windowed and security.py's is cumulative."""
    if score >= RISK_HIGH_MIN:
        return "HIGH"
    if score >= RISK_MEDIUM_MIN:
        return "MEDIUM"
    return "LOW"


# ---------------- Retention configuration (Phase 14) ----------------
#
# 0 (or any value <= 0) means "keep indefinitely" for that class of data,
# which is the backward-compatible default: an existing installation that
# sets nothing never silently loses records. purge_expired() only ever
# deletes rows strictly older than a positive, explicitly configured
# retention period.

RETENTION_TIMELINE_DAYS = envutil.env_int("MEMBER_RETENTION_TIMELINE_DAYS", 0)
RETENTION_IDENTITY_DAYS = envutil.env_int("MEMBER_RETENTION_IDENTITY_DAYS", 0)
RETENTION_JOIN_DAYS = envutil.env_int("MEMBER_RETENTION_JOIN_DAYS", 0)
RETENTION_RISK_SNAPSHOT_DAYS = envutil.env_int("MEMBER_RETENTION_RISK_SNAPSHOT_DAYS", 90)

# Storing verbatim message text is the most privacy-sensitive thing this
# system can do, so it is opt-in per deployment rather than on by default.
# When off, evidence capture still records structural facts (message id,
# chat id, user id, timestamps, hashes) but no message body.
STORE_MESSAGE_CONTENT = envutil.env_bool("MEMBER_STORE_MESSAGE_CONTENT", "true")


# ---------------- Result objects ----------------

@dataclass
class RiskReason:
    """One itemised contribution to a risk score. `count` is how many
    observations of this kind fell inside the window, `points` is what it
    actually added after the per-signal cap."""
    code: str
    label: str
    count: int
    weight: int
    points: int

    def as_dict(self) -> dict:
        return {"code": self.code, "label": self.label, "count": self.count,
                "weight": self.weight, "points": self.points}


@dataclass
class RiskAssessment:
    chat_id: int
    user_id: int
    score: int
    level: str
    window_seconds: int
    computed_at: int
    reasons: List[RiskReason] = field(default_factory=list)
    # security.py's separate cumulative counter, reported as-is for
    # comparison. Never mixed into `score`.
    cumulative_risk_score: int = 0
    cumulative_event_count: int = 0

    def as_dict(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "user_id": self.user_id,
            "score": self.score,
            "level": self.level,
            "window_seconds": self.window_seconds,
            "computed_at": self.computed_at,
            "reasons": [r.as_dict() for r in self.reasons],
            "cumulative_risk_score": self.cumulative_risk_score,
            "cumulative_event_count": self.cumulative_event_count,
            "disclaimer": RISK_DISCLAIMER,
        }


# Attached to every risk assessment and every rendered risk report. The
# wording is deliberate: a score is a queue-ordering hint, not a finding
# of fact about a person.
RISK_DISCLAIMER = (
    "คะแนนความเสี่ยงเป็นเครื่องมือช่วยจัดลำดับการตรวจสอบของผู้ดูแลเท่านั้น "
    "คำนวณจากเหตุการณ์ที่บอทสังเกตเห็นจริงในกลุ่มนี้ ไม่ใช่ข้อพิสูจน์ว่าผู้ใช้ทำผิด "
    "และไม่ใช่การระบุตัวตนหรือพฤติกรรมนอกกลุ่ม"
)

# Attached to every pattern-analysis result. Pattern similarity is never
# identity attribution; see find_correlated_activity().
PATTERN_DISCLAIMER = (
    "รูปแบบที่คล้ายกันคือ 'กิจกรรมที่มีความสัมพันธ์กัน' ซึ่งต้องให้ผู้ดูแลตรวจสอบต่อ "
    "ไม่ใช่ข้อพิสูจน์ว่าบัญชีเหล่านี้เป็นคนเดียวกัน"
)


@dataclass
class ObserveResult:
    """What record_observation() actually changed, so the caller can turn
    a real observed change into a timeline entry without re-querying."""
    member_ref: str
    created: bool = False
    username_changed: bool = False
    display_name_changed: bool = False
    first_message: bool = False
    previous_username: Optional[str] = None
    previous_display_name: Optional[str] = None


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def member_intel_db_init() -> None:
    """Create this module's tables and indexes. Idempotent: safe to call
    on every boot and on an existing installation. Never drops, alters or
    reads another module's tables."""
    conn = _conn()

    # Identity registry. (chat_id, user_id) is the primary key because
    # membership, display name and moderation history are all per-chat;
    # user_id alone is the stable identity ACROSS chats and is indexed
    # separately for that lookup.
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_members (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        member_ref TEXT NOT NULL,
        username TEXT,
        display_name TEXT,
        is_bot INTEGER NOT NULL DEFAULT 0,
        membership_status TEXT NOT NULL DEFAULT 'UNKNOWN',
        first_seen_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        first_seen_chat_id INTEGER,
        joined_at INTEGER,
        left_at INTEGER,
        join_count INTEGER NOT NULL DEFAULT 0,
        leave_count INTEGER NOT NULL DEFAULT 0,
        observed_message_count INTEGER NOT NULL DEFAULT 0,
        first_message_at INTEGER,
        last_message_at INTEGER,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_members_user ON mi_members (user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_members_username ON mi_members (username)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_members_last_seen "
                 "ON mi_members (chat_id, last_seen_at)")

    # Identity history: append-only snapshots of observed changes. A row
    # exists only because the bot saw the old value and then saw a
    # different new value; nothing is back-filled or inferred.
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_identity_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        field TEXT NOT NULL,
        old_value TEXT,
        new_value TEXT,
        observed_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_identity_user "
                 "ON mi_identity_history (chat_id, user_id, observed_at)")

    conn.execute("""CREATE TABLE IF NOT EXISTS mi_timeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        actor_user_id INTEGER,
        message_id INTEGER,
        incident_id INTEGER,
        detail TEXT,
        meta_json TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_timeline_user "
                 "ON mi_timeline (chat_id, user_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_timeline_chat_time "
                 "ON mi_timeline (chat_id, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_timeline_incident "
                 "ON mi_timeline (incident_id)")

    # Entry/invite tracking. invite_link* columns are NULL whenever
    # Telegram did not supply them -- which is the common case. Readers
    # must render NULL as UNAVAILABLE, never as "no invite link used".
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_join_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        old_status TEXT,
        new_status TEXT,
        via_join_request INTEGER NOT NULL DEFAULT 0,
        via_chat_folder_link INTEGER NOT NULL DEFAULT 0,
        invite_link TEXT,
        invite_link_name TEXT,
        invite_link_creator_id INTEGER,
        invite_link_creator_username TEXT,
        actor_user_id INTEGER,
        observed_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_join_user "
                 "ON mi_join_events (chat_id, user_id, observed_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_join_link "
                 "ON mi_join_events (chat_id, invite_link)")

    # Risk snapshots: what the engine said at a point in time, with the
    # reasons. Kept so a later moderation decision can be explained even
    # after the underlying window has rolled past.
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_risk_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        score INTEGER NOT NULL,
        level TEXT NOT NULL,
        window_seconds INTEGER NOT NULL,
        reasons_json TEXT NOT NULL,
        computed_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_risk_user "
                 "ON mi_risk_snapshots (chat_id, user_id, computed_at)")

    # Message fingerprints for conservative pattern analysis. Stores a
    # hash, never the text: enough to notice "the same message from five
    # accounts", not enough to reconstruct a conversation.
    conn.execute("""CREATE TABLE IF NOT EXISTS mi_message_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        text_hash TEXT NOT NULL,
        url_host TEXT,
        message_id INTEGER,
        observed_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_pattern_hash "
                 "ON mi_message_patterns (chat_id, text_hash, observed_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_mi_pattern_host "
                 "ON mi_message_patterns (chat_id, url_host, observed_at)")

    conn.commit()
    conn.close()
    logger.info("MEMBER INTEL DATABASE: OK")


# ---------------- Internal helpers ----------------

def _now(now: Optional[int] = None) -> int:
    return int(now) if now is not None else int(time.time())


def _clean(value: Optional[str], max_len: int) -> Optional[str]:
    """Normalizes untrusted free text: None stays None, blank becomes
    None, everything else is stripped and hard-capped. Stored as inert
    data -- never interpreted, never used in a permission decision."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_len]


def _member_ref(chat_id: int, user_id: int) -> str:
    """Stable internal record id. Derived (not random) so the same member
    always has the same reference across restarts and re-imports, and so
    it can be recomputed for lookup without a table scan. It is an
    internal handle only -- it is not a secret and carries no authority."""
    digest = hashlib.sha256(f"{chat_id}:{user_id}".encode("utf-8")).hexdigest()
    return f"MBR-{digest[:12].upper()}"


def _json_dump(meta: Optional[dict]) -> Optional[str]:
    """Canonical, bounded JSON for metadata columns. sort_keys makes the
    output byte-stable, which member_incident.py's integrity hashing
    depends on."""
    if not meta:
        return None
    try:
        text = json.dumps(meta, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        logger.warning("MEMBER INTEL | meta ไม่สามารถแปลงเป็น JSON ได้ — เก็บเป็นค่าว่าง")
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


def _limit(limit: Optional[int]) -> int:
    if limit is None:
        return DEFAULT_PAGE_LIMIT
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return DEFAULT_PAGE_LIMIT
    if value <= 0:
        return DEFAULT_PAGE_LIMIT
    return min(value, MAX_PAGE_LIMIT)


_URL_HOST_RE = re.compile(r"https?://([^/\s:]+)|(?:^|\s)(?:www\.)([^/\s:]+)", re.IGNORECASE)


def _first_url_host(text: str) -> Optional[str]:
    """Lowercased host of the first URL in `text`, or None. Deliberately
    minimal: detection.py owns real link policy: this is only the
    grouping key for "the same host promoted by several accounts"."""
    match = _URL_HOST_RE.search(text or "")
    if not match:
        return None
    host = match.group(1) or match.group(2) or ""
    host = host.strip().lower().rstrip(".")
    return host[:MAX_USERNAME_LEN] or None


def _text_fingerprint(text: str) -> str:
    """SHA-256 over whitespace-collapsed, casefolded text. A fingerprint,
    not a copy: it supports "identical message from N accounts" without
    retaining the message itself."""
    normalized = " ".join((text or "").split()).casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------- Phase 1/2: Identity registry + history ----------------

def get_member(chat_id: int, user_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM mi_members WHERE chat_id=? AND user_id=?",
        (int(chat_id), int(user_id)),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def find_members_by_username(username: str, limit: Optional[int] = None) -> List[dict]:
    """Look up by CURRENT username. Usernames are mutable and reusable, so
    this is a convenience lookup only -- callers must treat user_id as the
    identity and should also check mi_identity_history for past holders."""
    handle = (username or "").strip().lstrip("@")
    if not handle:
        return []
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM mi_members WHERE username=? COLLATE NOCASE "
        "ORDER BY last_seen_at DESC LIMIT ?",
        (handle[:MAX_USERNAME_LEN], _limit(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def find_historic_username_holders(username: str, limit: Optional[int] = None) -> List[dict]:
    """Accounts that were ever OBSERVED holding this username, from
    identity history. Answers "who was @alpha in March?" without
    pretending the current holder was always the holder."""
    handle = (username or "").strip().lstrip("@")
    if not handle:
        return []
    conn = _conn()
    rows = conn.execute(
        "SELECT chat_id, user_id, old_value, new_value, observed_at "
        "FROM mi_identity_history "
        "WHERE field=? AND (old_value=? COLLATE NOCASE OR new_value=? COLLATE NOCASE) "
        "ORDER BY observed_at DESC LIMIT ?",
        (IdentityField.USERNAME.value, handle, handle, _limit(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _record_identity_change(conn, chat_id: int, user_id: int, field_name: str,
                            old_value: Optional[str], new_value: Optional[str],
                            observed_at: int) -> None:
    conn.execute(
        "INSERT INTO mi_identity_history (chat_id, user_id, field, old_value, new_value, "
        "observed_at) VALUES (?, ?, ?, ?, ?, ?)",
        (int(chat_id), int(user_id), field_name, old_value, new_value, observed_at),
    )


def record_observation(chat_id: int, user_id: int, username=UNSET,
                       display_name=UNSET, is_bot: bool = False,
                       counts_as_message: bool = False,
                       message_id: Optional[int] = None,
                       now: Optional[int] = None) -> ObserveResult:
    """Upsert what the bot just observed about one account, and append an
    identity-history row for each field that genuinely CHANGED.

    Called on every group message, so it is deliberately cheap: one SELECT
    plus one UPSERT, plus at most two history INSERTs. Returns what
    changed so the caller can write timeline entries without re-reading.

    Passing username=None means "Telegram told us this account has no
    username", which IS an observation: combined with a previously
    observed handle it records a genuine "username removed" event.
    Omitting the argument entirely (the UNSET default) means "no
    information this time" and never writes a change -- see _Unset.

    An account that never had a username stays silent either way: a
    change is recorded only when the observed value actually differs from
    what was already on record."""
    chat_id, user_id = int(chat_id), int(user_id)
    ts = _now(now)
    username_known = not isinstance(username, _Unset)
    display_known = not isinstance(display_name, _Unset)
    handle = _clean(username, MAX_USERNAME_LEN) if username_known else None
    if handle:
        handle = handle.lstrip("@") or None
    name = _clean(display_name, MAX_DISPLAY_NAME_LEN) if display_known else None

    existing = get_member(chat_id, user_id)
    ref = _member_ref(chat_id, user_id)
    result = ObserveResult(member_ref=ref)

    conn = _conn()
    try:
        if existing is None:
            conn.execute(
                "INSERT INTO mi_members (chat_id, user_id, member_ref, username, display_name, "
                "is_bot, membership_status, first_seen_at, last_seen_at, first_seen_chat_id, "
                "observed_message_count, first_message_at, last_message_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (chat_id, user_id, ref, handle, name, 1 if is_bot else 0,
                 MembershipStatus.UNKNOWN.value, ts, ts, chat_id,
                 1 if counts_as_message else 0,
                 ts if counts_as_message else None,
                 ts if counts_as_message else None),
            )
            result.created = True
            result.first_message = bool(counts_as_message)
        else:
            old_handle = existing["username"]
            old_name = existing["display_name"]
            # Only a value the caller actually observed can change the
            # record. An omitted display_name must never erase a name we
            # already saw, and must never look like a rename.
            if display_known and name is not None and name != old_name:
                _record_identity_change(conn, chat_id, user_id,
                                        IdentityField.DISPLAY_NAME.value,
                                        old_name, name, ts)
                result.display_name_changed = True
                result.previous_display_name = old_name
            # Username: a change to None is real information ("removed"),
            # but only when the caller actually observed the absence and
            # a handle was previously on record.
            if username_known and handle != old_handle and (
                    handle is not None or old_handle is not None):
                _record_identity_change(conn, chat_id, user_id,
                                        IdentityField.USERNAME.value,
                                        old_handle, handle, ts)
                result.username_changed = True
                result.previous_username = old_handle

            result.first_message = bool(counts_as_message
                                        and existing["first_message_at"] is None)
            # username: overwritten only when observed this time (so an
            # omitted field cannot blank a handle we already know); a NULL
            # that WAS observed does overwrite, because that is a removal.
            conn.execute(
                "UPDATE mi_members SET "
                "username = CASE WHEN ? THEN ? ELSE username END, "
                "display_name = COALESCE(?, display_name), "
                "is_bot=?, last_seen_at=?, "
                "observed_message_count = observed_message_count + ?, "
                "first_message_at = COALESCE(first_message_at, ?), "
                "last_message_at = COALESCE(?, last_message_at) "
                "WHERE chat_id=? AND user_id=?",
                (1 if username_known else 0, handle, name, 1 if is_bot else 0, ts,
                 1 if counts_as_message else 0,
                 ts if counts_as_message else None,
                 ts if counts_as_message else None,
                 chat_id, user_id),
            )
        conn.commit()
    finally:
        conn.close()

    if result.username_changed or result.display_name_changed:
        changed = []
        if result.username_changed:
            changed.append(f"username: {result.previous_username or UNAVAILABLE} -> "
                           f"{handle or UNAVAILABLE}")
        if result.display_name_changed:
            changed.append("display_name เปลี่ยน")
        add_timeline_event(
            chat_id, user_id, TimelineEvent.IDENTITY_CHANGED,
            detail="; ".join(changed),
            meta={"username": handle or UNAVAILABLE,
                  "previous_username": result.previous_username or UNAVAILABLE},
            now=ts,
        )
    if result.first_message:
        add_timeline_event(chat_id, user_id, TimelineEvent.FIRST_MESSAGE,
                           message_id=message_id, now=ts)
    return result


def get_identity_history(chat_id: int, user_id: int,
                         limit: Optional[int] = None) -> List[dict]:
    """Observed identity changes, newest first. An empty list means the
    bot never observed a change -- NOT that the account never changed
    name before the bot was watching."""
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM mi_identity_history WHERE chat_id=? AND user_id=? "
        "ORDER BY observed_at DESC, id DESC LIMIT ?",
        (int(chat_id), int(user_id), _limit(limit)),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def build_identity_timeline(chat_id: int, user_id: int,
                            limit: Optional[int] = None) -> dict:
    """Oldest-first identity timeline plus the current state, shaped for
    reporting. `unknown_before` is the first moment the bot saw this
    account: anything earlier is genuinely unknown and reports say so."""
    member = get_member(chat_id, user_id)
    history = get_identity_history(chat_id, user_id, limit=limit)
    history.reverse()
    entries = []
    for row in history:
        entries.append({
            "observed_at": row["observed_at"],
            "field": row["field"],
            "from": row["old_value"] or UNAVAILABLE,
            "to": row["new_value"] or UNAVAILABLE,
        })
    return {
        "member_ref": member["member_ref"] if member else _member_ref(chat_id, user_id),
        "user_id": int(user_id),
        "chat_id": int(chat_id),
        "known": member is not None,
        "current_username": (member["username"] if member and member["username"]
                             else UNAVAILABLE),
        "current_display_name": (member["display_name"] if member and member["display_name"]
                                 else UNAVAILABLE),
        "unknown_before": member["first_seen_at"] if member else None,
        "entries": entries,
    }


# ---------------- Phase 3: Activity timeline ----------------

def add_timeline_event(chat_id: int, user_id: int, event_type, actor_user_id=None,
                       message_id: Optional[int] = None,
                       incident_id: Optional[int] = None,
                       detail: str = "", meta: Optional[dict] = None,
                       now: Optional[int] = None) -> Optional[int]:
    """Append one observable event. Returns the row id, or None if the
    event type is unknown (rejected rather than stored, so the timeline
    can never contain an event this module cannot explain).

    `actor_user_id` is the administrator/account that CAUSED the event and
    must be left None unless the bot actually observed who acted -- an
    invented actor would make the log lie about who did what."""
    value = event_type.value if isinstance(event_type, TimelineEvent) else str(event_type)
    if value not in VALID_TIMELINE_EVENTS:
        logger.warning("MEMBER TIMELINE | ไม่รู้จัก event_type=%r — ไม่บันทึก", value)
        return None

    ts = _now(now)
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO mi_timeline (chat_id, user_id, event_type, actor_user_id, message_id, "
        "incident_id, detail, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (int(chat_id), int(user_id), value,
         int(actor_user_id) if actor_user_id is not None else None,
         int(message_id) if message_id is not None else None,
         int(incident_id) if incident_id is not None else None,
         _clean(detail, MAX_DETAIL_LEN), _json_dump(meta), ts),
    )
    event_id = cur.lastrowid
    conn.commit()
    conn.close()
    logger.info("MEMBER TIMELINE | chat=%s user=%s event=%s", chat_id, user_id, value)
    return event_id


def get_timeline(chat_id: int, user_id: int, limit: Optional[int] = None,
                 since: Optional[int] = None, until: Optional[int] = None,
                 event_types: Optional[List[str]] = None) -> List[dict]:
    """Chronological reconstruction for one account, newest first.

    `event_types` is filtered through VALID_TIMELINE_EVENTS and bound as
    parameters -- the IN clause is built from a validated whitelist, never
    from caller text."""
    sql = ["SELECT * FROM mi_timeline WHERE chat_id=? AND user_id=?"]
    params: List[Any] = [int(chat_id), int(user_id)]
    if since is not None:
        sql.append("AND created_at >= ?")
        params.append(int(since))
    if until is not None:
        sql.append("AND created_at <= ?")
        params.append(int(until))
    if event_types:
        allowed = [t for t in event_types if t in VALID_TIMELINE_EVENTS]
        if not allowed:
            return []
        sql.append("AND event_type IN (%s)" % ",".join("?" for _ in allowed))
        params.extend(allowed)
    sql.append("ORDER BY created_at DESC, id DESC LIMIT ?")
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


def get_chat_timeline(chat_id: int, limit: Optional[int] = None,
                      since: Optional[int] = None) -> List[dict]:
    """Group-wide timeline, newest first -- for reconstructing an incident
    that involved more than one account."""
    sql = ["SELECT * FROM mi_timeline WHERE chat_id=?"]
    params: List[Any] = [int(chat_id)]
    if since is not None:
        sql.append("AND created_at >= ?")
        params.append(int(since))
    sql.append("ORDER BY created_at DESC, id DESC LIMIT ?")
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


# ---------------- Phase 4: Entry & invite tracking ----------------

def observe_membership_change(chat_id: int, user_id: int, old_status: Optional[str],
                              new_status: Optional[str],
                              username=UNSET,
                              display_name=UNSET,
                              is_bot: bool = False,
                              invite_link: Optional[str] = None,
                              invite_link_name: Optional[str] = None,
                              invite_link_creator_id: Optional[int] = None,
                              invite_link_creator_username: Optional[str] = None,
                              via_join_request: bool = False,
                              via_chat_folder_link: bool = False,
                              actor_user_id: Optional[int] = None,
                              now: Optional[int] = None) -> dict:
    """Record one observed membership transition (join / leave / rejoin /
    restrict / ban / promote), with invite attribution ONLY as supplied.

    On invite-link attribution, honestly: Telegram populates
    ChatMemberUpdated.invite_link for a join only in limited cases (the
    bot must be an administrator, and the join must have used a link the
    bot is allowed to see -- typically a link created by the bot itself or
    otherwise visible to it). Joins via the public group username, via
    another admin's link the bot cannot see, or via being added by a
    member carry no link at all. Callers pass what Telegram gave them;
    anything absent is stored as NULL and rendered as UNAVAILABLE. This
    function never derives, guesses or back-fills an invite link.

    `actor_user_id` is the account that performed the change when Telegram
    identifies one (the administrator in `from_user` of the update). For a
    self-join it is the joining user; it is never invented."""
    chat_id, user_id = int(chat_id), int(user_id)
    ts = _now(now)

    old_norm = _normalize_status(old_status)
    new_norm = _normalize_status(new_status)
    was_in = _status_is_present(old_norm)
    is_in = _status_is_present(new_norm)

    record_observation(chat_id, user_id, username=username, display_name=display_name,
                       is_bot=is_bot, now=ts)
    existing = get_member(chat_id, user_id)

    kind = None
    timeline_event = None
    if is_in and not was_in:
        # Rejoin only when a previous departure was actually observed.
        rejoin = bool(existing and (existing["leave_count"] or 0) > 0)
        kind = JoinKind.REJOINED.value if rejoin else JoinKind.JOINED.value
        timeline_event = (TimelineEvent.REJOINED if rejoin else TimelineEvent.JOINED)
    elif was_in and not is_in:
        kind = JoinKind.LEFT.value
        timeline_event = TimelineEvent.LEFT

    conn = _conn()
    try:
        if kind is not None:
            conn.execute(
                "INSERT INTO mi_join_events (chat_id, user_id, kind, old_status, new_status, "
                "via_join_request, via_chat_folder_link, invite_link, invite_link_name, "
                "invite_link_creator_id, invite_link_creator_username, actor_user_id, "
                "observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (chat_id, user_id, kind, old_norm, new_norm,
                 1 if via_join_request else 0, 1 if via_chat_folder_link else 0,
                 _clean(invite_link, MAX_DETAIL_LEN),
                 _clean(invite_link_name, MAX_DISPLAY_NAME_LEN),
                 int(invite_link_creator_id) if invite_link_creator_id is not None else None,
                 _clean(invite_link_creator_username, MAX_USERNAME_LEN),
                 int(actor_user_id) if actor_user_id is not None else None, ts),
            )
        if kind in (JoinKind.JOINED.value, JoinKind.REJOINED.value):
            conn.execute(
                "UPDATE mi_members SET membership_status=?, joined_at=?, "
                "join_count = join_count + 1 WHERE chat_id=? AND user_id=?",
                (new_norm, ts, chat_id, user_id),
            )
        elif kind == JoinKind.LEFT.value:
            conn.execute(
                "UPDATE mi_members SET membership_status=?, left_at=?, "
                "leave_count = leave_count + 1 WHERE chat_id=? AND user_id=?",
                (new_norm, ts, chat_id, user_id),
            )
        else:
            conn.execute(
                "UPDATE mi_members SET membership_status=? WHERE chat_id=? AND user_id=?",
                (new_norm, chat_id, user_id),
            )
        conn.commit()
    finally:
        conn.close()

    # Status transitions that are moderation outcomes get their own
    # timeline entry, because "restricted" and "banned" are what an
    # investigation actually needs to see.
    status_event = _status_timeline_event(old_norm, new_norm)
    meta = {
        "old_status": old_norm,
        "new_status": new_norm,
        "invite_link": _clean(invite_link, MAX_DETAIL_LEN) or UNAVAILABLE,
        "invite_link_name": _clean(invite_link_name, MAX_DISPLAY_NAME_LEN) or UNAVAILABLE,
        "invite_link_creator_id": (invite_link_creator_id
                                   if invite_link_creator_id is not None else UNAVAILABLE),
        "via_join_request": bool(via_join_request),
        "via_chat_folder_link": bool(via_chat_folder_link),
    }
    # When a specific moderation outcome describes the SAME transition,
    # emit only that one. A ban is a departure, but recording it as both
    # BANNED and a plain LEFT would let a reader conclude the account
    # left voluntarily -- two events for one fact, one of them
    # misleading. The join_events row still carries old/new status, so
    # nothing is lost.
    if status_event is not None:
        add_timeline_event(chat_id, user_id, status_event, actor_user_id=actor_user_id,
                           detail=f"{old_norm} -> {new_norm}", meta=meta, now=ts)
    elif timeline_event is not None:
        add_timeline_event(chat_id, user_id, timeline_event, actor_user_id=actor_user_id,
                           detail=f"{old_norm} -> {new_norm}", meta=meta, now=ts)

    return {"kind": kind or "STATUS_CHANGE", "old_status": old_norm, "new_status": new_norm,
            "invite_attribution_available": invite_link is not None}


def _normalize_status(status: Optional[str]) -> str:
    """Maps python-telegram-bot's ChatMemberStatus strings (lowercase,
    e.g. 'member', 'kicked', 'creator') onto MembershipStatus without
    importing telegram. Unknown values become UNKNOWN rather than being
    stored verbatim, so the column stays a closed vocabulary."""
    if not status:
        return MembershipStatus.UNKNOWN.value
    key = str(status).strip().upper()
    if key == "KICKED":
        return MembershipStatus.BANNED.value
    if key == "OWNER":
        return MembershipStatus.CREATOR.value
    if key in VALID_MEMBERSHIP_STATUSES:
        return key
    return MembershipStatus.UNKNOWN.value


_PRESENT_STATUSES = frozenset({
    MembershipStatus.CREATOR.value, MembershipStatus.ADMINISTRATOR.value,
    MembershipStatus.MEMBER.value, MembershipStatus.RESTRICTED.value,
})


def _status_is_present(status: str) -> bool:
    """Whether the status means "currently in the chat". RESTRICTED counts
    as present because a restricted member has not left; Telegram also
    uses RESTRICTED with is_member=False, which callers surface as LEFT
    via new_status instead."""
    return status in _PRESENT_STATUSES


def _status_timeline_event(old_status: str, new_status: str) -> Optional[TimelineEvent]:
    if new_status == old_status:
        return None
    if new_status == MembershipStatus.BANNED.value:
        return TimelineEvent.BANNED
    # Any move off BANNED is an unban, including BANNED -> LEFT, which is
    # what Telegram actually sends for a plain unban (the ban is lifted
    # without the account being re-added). Requiring the new status to be
    # "present" would silently drop the most common unban from the
    # timeline while still logging the admin action -- an investigation
    # would show a ban with no visible end.
    if old_status == MembershipStatus.BANNED.value:
        return TimelineEvent.UNBANNED
    if new_status == MembershipStatus.RESTRICTED.value:
        return TimelineEvent.RESTRICTED
    if old_status == MembershipStatus.RESTRICTED.value and new_status == MembershipStatus.MEMBER.value:
        return TimelineEvent.UNRESTRICTED
    if new_status == MembershipStatus.ADMINISTRATOR.value:
        return TimelineEvent.PROMOTED
    if old_status == MembershipStatus.ADMINISTRATOR.value and new_status == MembershipStatus.MEMBER.value:
        return TimelineEvent.DEMOTED
    return None


def get_join_history(chat_id: int, user_id: int, limit: Optional[int] = None) -> List[dict]:
    """Observed join/leave/rejoin records, newest first. invite_link*
    columns are NULL when Telegram did not supply them; callers must not
    read NULL as "did not use an invite link"."""
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM mi_join_events WHERE chat_id=? AND user_id=? "
        "ORDER BY observed_at DESC, id DESC LIMIT ?",
        (int(chat_id), int(user_id), _limit(limit)),
    ).fetchall()
    conn.close()
    out = []
    for row in rows:
        item = dict(row)
        item["invite_attribution"] = item["invite_link"] or UNAVAILABLE
        out.append(item)
    return out


def get_invite_link_stats(chat_id: int, limit: Optional[int] = None,
                          since: Optional[int] = None) -> dict:
    """Aggregate join counts per invite link, for spotting one link
    bringing in a burst of accounts.

    `joins_without_attribution` is reported as a first-class number, not
    hidden: in most groups it is the majority of joins, and a report that
    only showed attributed links would badly mislead an administrator
    about coverage."""
    params: List[Any] = [int(chat_id), JoinKind.JOINED.value, JoinKind.REJOINED.value]
    time_clause = ""
    if since is not None:
        time_clause = " AND observed_at >= ?"
        params.append(int(since))

    conn = _conn()
    attributed = conn.execute(
        "SELECT invite_link, invite_link_name, invite_link_creator_id, "
        "invite_link_creator_username, COUNT(*) AS joins, MIN(observed_at) AS first_join, "
        "MAX(observed_at) AS last_join FROM mi_join_events "
        "WHERE chat_id=? AND kind IN (?, ?) AND invite_link IS NOT NULL" + time_clause +
        " GROUP BY invite_link ORDER BY joins DESC LIMIT ?",
        params + [_limit(limit)],
    ).fetchall()
    unattributed = conn.execute(
        "SELECT COUNT(*) AS n FROM mi_join_events "
        "WHERE chat_id=? AND kind IN (?, ?) AND invite_link IS NULL" + time_clause,
        params,
    ).fetchone()
    total = conn.execute(
        "SELECT COUNT(*) AS n FROM mi_join_events WHERE chat_id=? AND kind IN (?, ?)"
        + time_clause,
        params,
    ).fetchone()
    conn.close()

    return {
        "chat_id": int(chat_id),
        "total_observed_joins": total["n"] if total else 0,
        "joins_without_attribution": unattributed["n"] if unattributed else 0,
        "links": [dict(r) for r in attributed],
        "note": ("Telegram ให้ข้อมูลลิงก์เชิญเฉพาะบางกรณี (บอทต้องเป็นผู้ดูแล และต้องเป็น "
                 "ลิงก์ที่บอทมองเห็นได้) การเข้ากลุ่มที่ไม่มีข้อมูลลิงก์จึงเป็นเรื่องปกติ "
                 "และไม่ได้หมายความว่า 'ไม่ได้ใช้ลิงก์เชิญ'"),
    }


# ---------------- Phase 5: Explainable risk engine ----------------

def _count_security_events(conn, chat_id: int, user_id: int, since: int) -> Dict[str, int]:
    """Counts security.py's OWN event rows inside the window. Read-only:
    this module never inserts into or updates security_events, so the two
    risk views can never disagree about the underlying facts."""
    rows = conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM security_events "
        "WHERE chat_id=? AND user_id=? AND created_at >= ? GROUP BY event_type",
        (chat_id, user_id, since),
    ).fetchall()
    return {r["event_type"]: r["n"] for r in rows}


def _count_timeline_events(conn, chat_id: int, user_id: int, since: int) -> Dict[str, int]:
    rows = conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM mi_timeline "
        "WHERE chat_id=? AND user_id=? AND created_at >= ? GROUP BY event_type",
        (chat_id, user_id, since),
    ).fetchall()
    return {r["event_type"]: r["n"] for r in rows}


def _count_confirmed_incidents(conn, chat_id: int, user_id: int, since: int) -> int:
    """Counts CONFIRMED incidents if member_incident.py's table exists.
    Guarded so the risk engine keeps working on an installation where the
    incident layer was never initialised -- the signal simply reports
    zero instead of raising."""
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM mi_incidents "
            "WHERE chat_id=? AND user_id=? AND status='CONFIRMED' AND opened_at >= ?",
            (chat_id, user_id, since),
        ).fetchone()
    except sqlite3.OperationalError:
        return 0
    return row["n"] if row else 0


def _count_duplicate_observations(conn, chat_id: int, user_id: int, since: int) -> int:
    """How many of this account's own messages inside the window repeated
    a fingerprint it had already sent. Derived from mi_message_patterns,
    which stores hashes only."""
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM ("
        "  SELECT text_hash, COUNT(*) AS c FROM mi_message_patterns "
        "  WHERE chat_id=? AND user_id=? AND observed_at >= ? "
        "  GROUP BY text_hash HAVING c > 1"
        ")",
        (chat_id, user_id, since),
    ).fetchone()
    return row["n"] if row else 0


def _cumulative_behavior(conn, chat_id: int, user_id: int) -> Dict[str, int]:
    row = conn.execute(
        "SELECT risk_score, event_count FROM user_behavior WHERE chat_id=? AND user_id=?",
        (chat_id, user_id),
    ).fetchone()
    if not row:
        return {"risk_score": 0, "event_count": 0}
    return {"risk_score": row["risk_score"], "event_count": row["event_count"]}


def assess_risk(chat_id: int, user_id: int, window_seconds: Optional[int] = None,
                now: Optional[int] = None, persist: bool = False) -> RiskAssessment:
    """Compute an explainable, windowed risk score for one account.

    Every point is attributable: the returned `reasons` list names each
    contributing signal, how many times it was observed, its configured
    weight and the points it actually added after its cap. The total is
    clamped to RISK_SCORE_MAX.

    This scores BEHAVIOUR the bot observed in this chat. It makes no claim
    about who the account holder is, about activity elsewhere, or about
    guilt -- see RISK_DISCLAIMER, which travels with every result."""
    chat_id, user_id = int(chat_id), int(user_id)
    ts = _now(now)
    window = int(window_seconds) if window_seconds else RISK_WINDOW_SECONDS
    if window <= 0:
        window = RISK_WINDOW_SECONDS
    since = ts - window

    conn = _conn()
    try:
        sec_counts = _count_security_events(conn, chat_id, user_id, since)
        tl_counts = _count_timeline_events(conn, chat_id, user_id, since)
        confirmed = _count_confirmed_incidents(conn, chat_id, user_id, since)
        duplicates = _count_duplicate_observations(conn, chat_id, user_id, since)
        cumulative = _cumulative_behavior(conn, chat_id, user_id)
    finally:
        conn.close()

    reasons: List[RiskReason] = []

    def _add(spec: RiskSignalSpec, count: int) -> None:
        if count <= 0:
            return
        points = min(spec.weight * count, spec.cap)
        reasons.append(RiskReason(spec.code, spec.label, count, spec.weight, points))

    for event_type, count in sorted(sec_counts.items()):
        spec = RISK_SIGNALS.get(event_type)
        if spec is None:
            # An event type security.py adds later contributes nothing
            # until it is given an explicit, reviewed weight here, rather
            # than silently inheriting a default. Unweighted signals are
            # still visible in the raw event list in the report.
            continue
        _add(spec, count)

    _add(RISK_SIGNALS["DUPLICATE_MESSAGE"], duplicates)

    for event_type, spec in RISK_TIMELINE_SIGNALS.items():
        _add(spec, tl_counts.get(event_type, 0))

    _add(RISK_CONFIRMED_INCIDENT, confirmed)

    score = min(RISK_SCORE_MAX, sum(r.points for r in reasons))
    assessment = RiskAssessment(
        chat_id=chat_id, user_id=user_id, score=score, level=risk_level(score),
        window_seconds=window, computed_at=ts, reasons=reasons,
        cumulative_risk_score=cumulative["risk_score"],
        cumulative_event_count=cumulative["event_count"],
    )

    if persist:
        conn = _conn()
        conn.execute(
            "INSERT INTO mi_risk_snapshots (chat_id, user_id, score, level, window_seconds, "
            "reasons_json, computed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (chat_id, user_id, score, assessment.level, window,
             json.dumps([r.as_dict() for r in reasons], ensure_ascii=False,
                        sort_keys=True, separators=(",", ":")), ts),
        )
        conn.commit()
        conn.close()
    return assessment


def get_risk_snapshots(chat_id: int, user_id: int, limit: Optional[int] = None) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM mi_risk_snapshots WHERE chat_id=? AND user_id=? "
        "ORDER BY computed_at DESC, id DESC LIMIT ?",
        (int(chat_id), int(user_id), _limit(limit)),
    ).fetchall()
    conn.close()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["reasons"] = json.loads(item.pop("reasons_json", "[]"))
        except (TypeError, ValueError):
            item["reasons"] = []
        out.append(item)
    return out


def top_risk_members(chat_id: int, limit: Optional[int] = None,
                     window_seconds: Optional[int] = None,
                     now: Optional[int] = None) -> List[RiskAssessment]:
    """Highest windowed risk first, for triage. Candidates are the accounts
    with any security event inside the window -- a member with no observed
    events cannot score above zero, so scanning the whole registry would
    only add cost."""
    ts = _now(now)
    window = int(window_seconds) if window_seconds else RISK_WINDOW_SECONDS
    since = ts - window
    n = _limit(limit)

    conn = _conn()
    rows = conn.execute(
        "SELECT user_id FROM ("
        "  SELECT user_id FROM security_events WHERE chat_id=? AND created_at >= ? "
        "  UNION "
        "  SELECT user_id FROM mi_timeline WHERE chat_id=? AND created_at >= ? "
        ") GROUP BY user_id",
        (int(chat_id), since, int(chat_id), since),
    ).fetchall()
    conn.close()

    assessments = [assess_risk(chat_id, r["user_id"], window_seconds=window, now=ts)
                   for r in rows]
    assessments.sort(key=lambda a: (-a.score, a.user_id))
    return assessments[:n]


# ---------------- Phase 11: Conservative pattern analysis ----------------

def record_message_pattern(chat_id: int, user_id: int, text: str,
                           message_id: Optional[int] = None,
                           now: Optional[int] = None) -> None:
    """Store a fingerprint (never the text) of one message, plus the first
    URL host if present. This is the only input to pattern analysis, and
    it is intentionally lossy: it can show that two accounts sent the same
    thing, and cannot reconstruct what they sent."""
    if not text or not text.strip():
        return
    ts = _now(now)
    conn = _conn()
    conn.execute(
        "INSERT INTO mi_message_patterns (chat_id, user_id, text_hash, url_host, "
        "message_id, observed_at) VALUES (?, ?, ?, ?, ?, ?)",
        (int(chat_id), int(user_id), _text_fingerprint(text), _first_url_host(text),
         int(message_id) if message_id is not None else None, ts),
    )
    conn.commit()
    conn.close()


PATTERN_MIN_ACCOUNTS = envutil.env_int("MEMBER_PATTERN_MIN_ACCOUNTS", 3)
PATTERN_WINDOW_SECONDS = envutil.env_int("MEMBER_PATTERN_WINDOW_SECONDS", 3600)


def find_correlated_activity(chat_id: int, window_seconds: Optional[int] = None,
                             min_accounts: Optional[int] = None,
                             limit: Optional[int] = None,
                             now: Optional[int] = None) -> dict:
    """Find activity that CORRELATES across accounts inside a time window.

    Reports two kinds of correlation, both deliberately weak claims:
      - identical_message: the same message fingerprint from several
        accounts ("possible coordinated posting").
      - shared_url_host: the same link host promoted by several accounts
        ("possible link campaign").

    What this is NOT: evidence that the accounts belong to one person.
    Shared text is what a forwarded joke, a quoted rule, a copied
    announcement and a paid campaign all look like. Every returned item
    carries verdict='REQUIRES_REVIEW' and the result carries
    PATTERN_DISCLAIMER. Nothing in this module ever emits a same-person
    conclusion, and no caller should synthesise one from these fields."""
    ts = _now(now)
    window = int(window_seconds) if window_seconds else PATTERN_WINDOW_SECONDS
    threshold = int(min_accounts) if min_accounts else PATTERN_MIN_ACCOUNTS
    threshold = max(2, threshold)
    since = ts - max(1, window)
    n = _limit(limit)

    conn = _conn()
    dup_rows = conn.execute(
        "SELECT text_hash, COUNT(DISTINCT user_id) AS accounts, COUNT(*) AS messages, "
        "MIN(observed_at) AS first_seen, MAX(observed_at) AS last_seen "
        "FROM mi_message_patterns WHERE chat_id=? AND observed_at >= ? "
        "GROUP BY text_hash HAVING accounts >= ? "
        "ORDER BY accounts DESC, messages DESC LIMIT ?",
        (int(chat_id), since, threshold, n),
    ).fetchall()
    host_rows = conn.execute(
        "SELECT url_host, COUNT(DISTINCT user_id) AS accounts, COUNT(*) AS messages, "
        "MIN(observed_at) AS first_seen, MAX(observed_at) AS last_seen "
        "FROM mi_message_patterns WHERE chat_id=? AND observed_at >= ? "
        "AND url_host IS NOT NULL GROUP BY url_host HAVING accounts >= ? "
        "ORDER BY accounts DESC, messages DESC LIMIT ?",
        (int(chat_id), since, threshold, n),
    ).fetchall()

    identical = []
    for row in dup_rows:
        users = conn.execute(
            "SELECT DISTINCT user_id FROM mi_message_patterns "
            "WHERE chat_id=? AND text_hash=? AND observed_at >= ? LIMIT ?",
            (int(chat_id), row["text_hash"], since, MAX_PAGE_LIMIT),
        ).fetchall()
        identical.append({
            "kind": "identical_message",
            "label": "ข้อความเหมือนกันจากหลายบัญชี (อาจเป็นรูปแบบที่ประสานกัน)",
            "fingerprint": row["text_hash"][:16],
            "account_count": row["accounts"],
            "message_count": row["messages"],
            "user_ids": [u["user_id"] for u in users],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "verdict": "REQUIRES_REVIEW",
        })

    shared_hosts = []
    for row in host_rows:
        users = conn.execute(
            "SELECT DISTINCT user_id FROM mi_message_patterns "
            "WHERE chat_id=? AND url_host=? AND observed_at >= ? LIMIT ?",
            (int(chat_id), row["url_host"], since, MAX_PAGE_LIMIT),
        ).fetchall()
        shared_hosts.append({
            "kind": "shared_url_host",
            "label": "หลายบัญชีโพสต์ลิงก์ปลายทางเดียวกัน (อาจเป็นแคมเปญลิงก์)",
            "url_host": row["url_host"],
            "account_count": row["accounts"],
            "message_count": row["messages"],
            "user_ids": [u["user_id"] for u in users],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "verdict": "REQUIRES_REVIEW",
        })
    conn.close()

    return {
        "chat_id": int(chat_id),
        "window_seconds": window,
        "min_accounts": threshold,
        "computed_at": ts,
        "identical_messages": identical,
        "shared_url_hosts": shared_hosts,
        "disclaimer": PATTERN_DISCLAIMER,
    }


# ---------------- Phase 14: Retention / purge ----------------

def _purge_table(conn, table: str, column: str, cutoff: int,
                 chat_id: Optional[int]) -> int:
    """Deletes rows older than `cutoff`. `table`/`column` are module
    constants chosen by purge_expired(), never caller input, so no
    identifier ever comes from user data."""
    sql = f"DELETE FROM {table} WHERE {column} < ?"
    params: List[Any] = [int(cutoff)]
    if chat_id is not None:
        sql += " AND chat_id=?"
        params.append(int(chat_id))
    cur = conn.execute(sql, params)
    return cur.rowcount or 0


# (table, timestamp column, retention-days setting name). Fixed table;
# the only variable is the configured number of days.
_PURGE_PLAN = (
    ("mi_timeline", "created_at", "RETENTION_TIMELINE_DAYS"),
    ("mi_identity_history", "observed_at", "RETENTION_IDENTITY_DAYS"),
    ("mi_join_events", "observed_at", "RETENTION_JOIN_DAYS"),
    ("mi_risk_snapshots", "computed_at", "RETENTION_RISK_SNAPSHOT_DAYS"),
    ("mi_message_patterns", "observed_at", "RETENTION_TIMELINE_DAYS"),
)


def retention_settings() -> Dict[str, int]:
    """Effective retention configuration, for /status-style transparency.
    0 means "keep indefinitely" (the default)."""
    return {
        "timeline_days": RETENTION_TIMELINE_DAYS,
        "identity_days": RETENTION_IDENTITY_DAYS,
        "join_days": RETENTION_JOIN_DAYS,
        "risk_snapshot_days": RETENTION_RISK_SNAPSHOT_DAYS,
        "store_message_content": STORE_MESSAGE_CONTENT,
    }


def purge_expired(chat_id: Optional[int] = None, actor_user_id: Optional[int] = None,
                  now: Optional[int] = None) -> Dict[str, int]:
    """Delete records past their configured retention period.

    A class of data with a retention of 0 (the default) is skipped
    entirely -- an operator who configures nothing never silently loses
    history. Returns the per-table delete counts and writes one audit
    entry so the deletion itself is accountable."""
    ts = _now(now)
    deleted: Dict[str, int] = {}
    module_globals = globals()

    conn = _conn()
    try:
        for table, column, setting in _PURGE_PLAN:
            days = int(module_globals.get(setting, 0) or 0)
            if days <= 0:
                continue
            cutoff = ts - days * 86400
            deleted[table] = deleted.get(table, 0) + _purge_table(conn, table, column,
                                                                  cutoff, chat_id)
        conn.commit()
    finally:
        conn.close()

    total = sum(deleted.values())
    if total:
        detail_text = ", ".join(f"{k}={v}" for k, v in sorted(deleted.items()) if v)
        write_audit_log(chat_id if chat_id is not None else 0, None, actor="system",
                        action="MEMBER_DATA_PURGED", detail=detail_text)
        logger.info("MEMBER INTEL PURGE | %s", detail_text)
    return deleted


def forget_member(chat_id: int, user_id: int, actor_user_id: int,
                  now: Optional[int] = None) -> Dict[str, int]:
    """Erase this module's records for one account in one chat.

    Scope is deliberately limited to the tables this module owns. It does
    NOT touch security.py's security_events/user_behavior/audit_log, and
    it does NOT touch member_incident.py's incidents, evidence or chain of
    custody -- deleting those would destroy an audit trail that may be
    required to justify an administrative action already taken, and each
    owning module has to make that call for itself. The audit entry this
    writes records the erasure as an event in its own right."""
    chat_id, user_id = int(chat_id), int(user_id)
    ts = _now(now)
    deleted: Dict[str, int] = {}
    conn = _conn()
    try:
        for table in ("mi_timeline", "mi_identity_history", "mi_join_events",
                      "mi_risk_snapshots", "mi_message_patterns", "mi_members"):
            cur = conn.execute(f"DELETE FROM {table} WHERE chat_id=? AND user_id=?",
                               (chat_id, user_id))
            deleted[table] = cur.rowcount or 0
        conn.commit()
    finally:
        conn.close()

    write_audit_log(chat_id, user_id, actor="user", action="MEMBER_RECORD_FORGOTTEN",
                    detail=f"actor={actor_user_id} rows=" +
                           ",".join(f"{k}:{v}" for k, v in sorted(deleted.items())))
    logger.info("MEMBER INTEL FORGET | chat=%s user=%s rows=%s", chat_id, user_id,
                sum(deleted.values()))
    return deleted


# ---------------- Aggregate read for reporting ----------------

def get_member_profile(chat_id: int, user_id: int,
                       timeline_limit: Optional[int] = None,
                       now: Optional[int] = None) -> dict:
    """Everything this module knows about one account in one chat, with
    facts and analysis kept in separate keys so member_report.py can
    render them under separate headings and never blur the two.

    `known=False` means the bot has no record at all -- the caller must
    report that as "no observation", not as "clean"."""
    chat_id, user_id = int(chat_id), int(user_id)
    member = get_member(chat_id, user_id)
    assessment = assess_risk(chat_id, user_id, now=now)
    return {
        "known": member is not None,
        "member": member,
        "member_ref": member["member_ref"] if member else _member_ref(chat_id, user_id),
        "identity_timeline": build_identity_timeline(chat_id, user_id),
        "join_history": get_join_history(chat_id, user_id),
        "timeline": get_timeline(chat_id, user_id, limit=timeline_limit),
        "risk": assessment.as_dict(),
    }
