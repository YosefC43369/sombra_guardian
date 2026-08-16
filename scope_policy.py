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