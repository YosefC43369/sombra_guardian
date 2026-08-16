"""
findings.py — Phase 4: Finding / Evidence / Case Management

Deterministic, offline record-keeping layer for bug-bounty findings a
researcher has already obtained through an authorized workflow, and
the evidence that backs them up. This module does not scan, probe,
crawl, exploit, or collect anything from a target — it only stores and
transitions records a human supplies.

This is a consumer of scope_policy.py, not a replacement for it:
create_finding() calls scope_policy.evaluate_target() for the
ALLOW/DENY decision and does not re-implement any domain/IP/CIDR
matching itself. If evaluate_target() denies, finding creation is
denied for the exact same reason — there is no separate, weaker check
here and no "is_admin" parameter anywhere in this module. Being a
Telegram administrator, a finding's creator, or an evidence submitter
is never sufficient authorization on its own; only a reviewed,
ACTIVE, currently-effective Authorization matched against an INCLUDE
scope rule (with no EXCLUDE match) can produce ALLOW.

Untrusted free-text fields (title, description, evidence description/
filename) are stored as ordinary data and are never parsed as
instructions or fed back into any policy/authorization/state-machine
decision. No field on a Finding or Evidence record is ever read by
evaluate_target() or by the state-transition checks below.

Design constraints (matches security.py / quota.py / analytics.py /
scope_policy.py):
- Standard library only (sqlite3, time, re, hashlib, dataclasses, enum).
- No network/API calls, no LLM calls, no background threads.
- No dependency on gemini.py/OpenAI — this layer must stay deterministic
  even if the AI provider is down, misconfigured, or removed entirely.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table (via write_audit_log) — no second database.
- Evidence file bytes are hashed (SHA-256) but never persisted to disk
  by this module and never executed/imported/interpreted as code —
  only the fingerprint + caller-supplied metadata is stored. Any actual
  file-blob storage subsystem is out of scope for this phase (see
  Phase 4 report, "Remaining Limitations").
"""

import re
import time
import sqlite3
import hashlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

from security import DB_PATH, write_audit_log
from scope_policy import get_program, evalute_target

logger = logging.getLogger("modbot.findings")

# ---------------- Enums / Constants ----------------

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    

class FindingStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    CONFIRMED = "CONFIRMED"
    DUPLICATE = "DUPLICATE"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"


class EvidenceType(str, Enum):
    TEXT = "TEXT"
    FILE = "FILE"
    IMAGE = "IMAGE"
    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    LOG = "LOG"
    SCREENSHOT = "SCREENSHOT"
    OTHER = "OTHER"
    
VALID_SEVERITIES = {s.value for s in Severity}
VALID_STATUSES = {s.value for s in FindingStatus}
VALID_EVIDENCE_TYPES = {t.value for t in EvidenceType}

# Deterministic finding lifecycle. DUPLICATE is reachable from any
# non-terminal state (a duplicate can be recognized at any triage
# stage, not only from TRIAGED) but is deliberately NOT settable via
# update_finding_status() — see the guard in that function. RESOLVED /
# REJECTED / DUPLICATE are terminal: no further transition is legal,
# so a resolved finding can't be silently reopened by an arbitrary
# status string.
_ALLOWED_TRANSITIONS = {
    FindingStatus.OPEN.value: {FindingStatus.TRIAGED.value, FindingStatus.REJECTED.value,
                                FindingStatus.DUPLICATE.value},
    FindingStatus.TRIAGED.value: {FindingStatus.CONFIRMED.value, FindingStatus.REJECTED.value,
                                   FindingStatus.DUPLICATE.value},
    FindingStatus.CONFIRMED.value: {FindingStatus.RESOLVED.value, FindingStatus.REJECTED.value,
                                     FindingStatus.DUPLICATE.value},
    FindingStatus.RESOLVED.value: set(),
    FindingStatus.REJECTED.value: set(),
    FindingStatus.DUPLICATE.value: set(),
}

MAX_TITLE_LEN = 200
MAX_DESCRIPTION_LEN = 4000
MAX_EVIDENCE_DESCRIPTION_LEN = 2000
MAX_RESOLUTION_LEN = 2000
MAX_EVIDENCE_BYTES = 15 * 1024 * 1024  # 15MB; matches gemini.py's MAX_MEDIA_BYTES cap by convention

# Filenames are metadata only (never used as a filesystem path — this
# module never writes evidence bytes to disk). Still enforced strictly:
# no separators, no traversal segments, conservative charset only.
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,198}$")