"""
bb_case.py — Phase 7: Bug Bounty Case Management.

A Case is the *management* layer that sits on top of an existing
Finding. The Finding stays the single source of truth for the technical
data (target, title, severity, scope decision); a Case only answers
"who is handling this, how urgently, and where is it in our workflow".

Deliberate non-responsibilities (these belong to modules that already
own them, and this module must never grow them):
  - Scope / authorization decisions -> scope_policy.evaluate_target().
    This module never imports it. A Case is downstream metadata and can
    never widen, narrow, or bypass what a Program authorizes.
  - Finding technical data and the Finding state machine -> findings.py.
    Case status is a *separate* state machine that runs alongside the
    Finding's, never overwrites it, and never writes to bb_findings.
  - Audit logging -> security.write_audit_log(). No second audit system.
  - Database location -> security.DB_PATH. No second database.

Design constraints (matches security.py / scope_policy.py / findings.py):
  - Standard library only.
  - CREATE TABLE IF NOT EXISTS only; idempotent init; never a
    destructive migration.
  - Every query parameterized. No SQL is ever built from user input.
  - Notes and timeline messages are inert data: stored, length-capped,
    and rendered as text. Never evaluated, never imported, never fed to
    a subprocess, and never consulted by any permission check.
"""