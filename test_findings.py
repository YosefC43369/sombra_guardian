"""
test_findings.py — Phase 4 test suite.

Same isolation pattern as test_scope_policy.py: each test gets a fresh,
isolated SQLite file (tempfile), so tests never share state and can run
in any order. Exercises findings.py through its real public API
(create_finding / update_finding_status / mark_duplicate / add_evidence /
verify_evidence), building programs/authorizations/scope through
scope_policy.py's real API rather than poking at internal tables —
that's the actual integration surface app.py calls.
"""

import os
import time
import tempfile
import unittest

import security
import scope_policy as sp
import findings as f


class FindingsTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        sp.DB_PATH = path
        f.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()
        f.findings_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass
            
    # ---- fixture helpers ----
    
    def _active_program(self, chat_id=1, admin=999):
        pid = sp.create_program(chat_id, "Acme Bug Bounty", created_by=admin)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, admin)
        return pid

    def _active_authorization(self, program_id, admin=999, reviewer=1000,
                               effective_at=None, expires_at=None, notes=""):
        aid = sp.import_authorization(
            program_id, source_type="email", actor_user_id=admin,
            source_reference="security@acme.test", authorization_reference="ACME-2026-01",
            effective_at=effective_at, expires_at=expires_at,
        )
        sp.review_authorization(aid, approve=True, reviewer_user_id=reviewer, notes=notes)
        return aid

    def _fully_authorized_program(self, include="example.com", chat_id=1, notes=""):
        pid = self._active_program(chat_id)
        self._active_authorization(pid, notes=notes)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           include, actor_user_id=999)
        return pid

    def _open_finding(self, program_id=None, target="example.com", title="XSS on login",
                       created_by=42):
        if program_id is None:
            program_id = self._fully_authorized_program(include=target)
        r = f.create_finding(program_id, target, title, created_by)
        self.assertTrue(r.ok, msg=r.reason)
        return r.finding_id, program_id

    # ================= FINDING CREATION =================