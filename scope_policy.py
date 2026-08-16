"""
scope_policy.py — Bug-Bounty Authorization + Scope Policy Foundation

Deterministic, offline, fail-closed policy layer for tracking
externally-sourced bug-bounty/pentest authorization and enforcing
scope boundaries. This module answers exactly one question —
"is this target currently authorized for testing, per the recorded
external authorization and scope rules?" — and nothing else.

This module does NOT perform, and must never be extended to perform:
HTTP requests, DNS resolution, WHOIS, crawling, port scanning,
vulnerability scanning, exploitation, payload generation, active
probing, subdomain/API/tech-stack discovery, or Dark-Web/OSINT/
personal- or corporate-intelligence collection of any kind. It has
no dependency on GEMINI_API_KEY / GPT_API_KEY and never sends any
target, authorization, or scope data to an LLM — every decision
below is ordinary, deterministic application logic.

CORE INVARIANT: Telegram administrator privilege is NEVER sufficient
authorization on its own. evaluate_target() has no "is_admin"
parameter and no code path in this module lets Telegram role
substitute for a reviewed Authorization Artifact. A target can only
reach ALLOW when ALL of the following hold:

  Program is ACTIVE
  + a human-reviewed (reviewed_by + reviewed_at present), currently
    ACTIVE, currently-effective, non-expired Authorization Artifact
    exists for that program
  + the target normalizes successfully (structural parsing, not a
    guess)
  + the target matches at least one INCLUDE scope rule and no
    EXCLUDE scope rule (EXCLUDE always wins)

Any missing, ambiguous, or unrecognized condition produces DENY.
UNKNOWN never becomes ALLOW — see evaluate_target()'s try/except,
which converts any unexpected internal error into DENY(POLICY_ERROR)
rather than propagating it.

Importing/recording an Authorization Artifact (import_authorization)
is deliberately NOT the same action as approving it
(review_authorization) — creating a record of an external source is
not authorization; a separate, explicitly logged human decision is.
This module never claims to have independently verified that an
external source_reference/authorization_reference is genuine — it
only records that a named human reviewed it and when.

Design constraints (matches security.py / quota.py / analytics.py):
- Standard library only (sqlite3, time, ipaddress, re, dataclasses,
  enum, urllib.parse).
- No network/API calls, no LLM calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table — no second database, no second audit system.
"""

import re
import time
import sqlite3
import logging
import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List
from urllib.parse import urlsplit

from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.scope_policy")

# ---------------- States ----------------

class ProgramStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"
  
class AuthorizationStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    REJECTED = "REJECTED"
    
class RuleType(str, Enum):
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class TargetType(str, Enum):
    DOMAIN = "DOMAIN"
    URL = "URL"
    IP = "IP"
    CIDR = "CIDR"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Reason(str, Enum):
    OK = "OK"
    PROGRAM_NOT_FOUND = "PROGRAM_NOT_FOUND"
    PROGRAM_NOT_ACTIVE = "PROGRAM_NOT_ACTIVE"
    AUTHORIZATION_NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
    AUTHORIZATION_NOT_REVIEWED = "AUTHORIZATION_NOT_REVIEWED"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    AUTHORIZATION_NOT_EFFECTIVE = "AUTHORIZATION_NOT_EFFECTIVE"
    TARGET_INVALID = "TARGET_INVALID"
    TARGET_OUT_OF_SCOPE = "TARGET_OUT_OF_SCOPE"
    TARGET_EXCLUDED = "TARGET_EXCLUDED"
    NO_INCLUDE_MATCH = "NO_INCLUDE_MATCH"
    POLICY_ERROR = "POLICY_ERROR"


VALID_PROGRAM_STATUSES = {s.value for s in ProgramStatus}
VALID_AUTH_STATUSES = {s.value for s in AuthorizationStatus}
VALID_RULE_TYPES = {t.value for t in RuleType}
VALID_TARGET_TYPES = {t.value for t in TargetType}

_DEFAULT_PORTS = {"http": 80, "https": 443}

@dataclass
class PolicyDecision:
    decision: str # Decision.ALLOW.value / Decision.DENY.value
    reason: str.  # Reason.*.value
    detail: str = ""
    
    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW.value
        
def _deny(reason: Reason, detail: str = "")
    return PolicyDecision(decision=Decision.DENY.value, reason=reason.value, detail=detail)
    
# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
def scope_policy_db_int() -> None:
    """Create policy-engine tables only. Reuses security.py's DB_PATH and
    audit_log table; never touches any other module's tables or data."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_programs (
        program_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PAUSED',
        metadata TEXT,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_programs_chat ON bb_programs (chat_id)")
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_authorizations (
        authorization_id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER NOT NULL,
        source_type TEXT NOT NULL,
        source_reference TEXT,
        authorization_reference TEXT,
        reviewed_by INTEGER,
        reviewed_at INTEGER,
        effective_at INTEGER,
        expires_at INTEGER,
        status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (program_id) REFERENCES bb_programs(program_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_auth_program ON bb_authorizations (program_id)")
    conn.execute("""CREATE TABLE IF NOT EXISTS bb_scope_rules (
        rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER NOT NULL,
        rule_type TEXT NOT NULL,
        target_type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (program_id) REFERENCES bb_programs(program_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bb_scope_program ON bb_scope_rules (program_id)")
    conn.commit()
    conn.close()
    logger.info("SCOPE POLICY DATABASE: OK")
    
# ---------------- Program ----------------

def create_program(chat_id: int, name: str, created_by: int, metadata: str = "") -> int:
    """Creates a Program in PAUSED status. A brand-new program is never
    ACTIVE by default — an admin must explicitly activate it via
    set_program_status(), which keeps 'program exists' distinct from
    'program may currently produce ALLOW', mirroring the artifact/review
    split in the Authorization section below."""
    now = int(time.())
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO bb_programs (chat_id, name, status, metadata, created_by, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (chat_id, name, ProgramStatus.PAUSED.value, metadata, created_by, now, now),
    )
    program_id = cur.lastrowid
    conn.commit()
    conn.close()
    write_audit_log(chat_id, created_by, actor="admin", action="PROGRAM_CREATED",
                     detail=f"program_id={program_id} name={name!r}")
    return program_id
    
def get_program(program_id: int) -> Optional