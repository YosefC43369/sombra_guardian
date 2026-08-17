"""
test_bb_report.py — Phase 6 test suite for bb_report.py.

Same isolation pattern as test_scope_policy.py / test_findings.py: each
test gets a fresh, isolated SQLite tempfile. Builds Programs/
Authorizations/Scope Rules/Findings/Evidence through the real
scope_policy.py / findings.py public APIs (not by poking at internal
tables), matching how bb_report.py itself reads them.
"""