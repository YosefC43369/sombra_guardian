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