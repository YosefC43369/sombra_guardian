"""
bb_report.py — Phase 6: Bug-Bounty Program Report (read-only)

Aggregates Program / Authorization / Scope Rule / Finding / Evidence
counts for a single Program into one Thai-language summary, mirroring
dashboard.py's read-only reporting pattern on the moderation side of
this bot.

Design constraints (matches dashboard.py):
- Owns NO tables of its own — there is no db_init function here.
  Reads exclusively through scope_policy.py's and findings.py's
  existing public APIs (get_program, list_authorizations,
  list_scope_rules, list_findings, list_evidence). In particular,
  "effective" authorization status (ACTIVE by stored column but
  actually past its expires_at) is computed by
  scope_policy.effective_authorization_status() exactly once and
  reused here — this module does not re-implement that check.
- Standard library only.
- No network/API calls, no LLM calls, no background threads.
- No scope-matching or ALLOW/DENY logic of any kind lives here — this
  module counts existing records; it never decides whether a target
  would be authorized. evaluate_target() is never called from here.
"""

import logging
from collections import Counter
from typing import Optional

from scope_policy import (
    get_program, list_authorizations, list_scope_rules, effective_authorization_status,
)
from findings import list_findings, list_evidence