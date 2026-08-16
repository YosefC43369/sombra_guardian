"""
test_scope_policy.py — Phase 2 test suite.

Each test gets a fresh, isolated SQLite file (tempfile), so tests never
share state and can run in any order. Exercises the module through its
real public API (create_program / import_authorization / review_authorization /
add_scope_rule / evaluate_target) rather than poking at internal tables,
since that's the actual integration surface app.py will call.
"""

import os
import time
import tempfile
import unittest

import security
import scope_policy as sp


class ScopePolicyTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        sp.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()

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
                               effective_at=None, expires_at=None):
        aid = sp.import_authorization(
            program_id, source_type="email", actor_user_id=admin,
            source_reference="security@acme.test", authorization_reference="ACME-2026-01",
            effective_at=effective_at, expires_at=expires_at,
        )
        sp.review_authorization(aid, approve=True, reviewer_user_id=reviewer)
        return aid

    def _fully_authorized_program(self, include="example.com", chat_id=1):
        pid = self._active_program(chat_id)
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           include, actor_user_id=999)
        return pid

    # ================= PROGRAM =================

    def test_program_missing_denies(self):
        d = sp.evaluate_target(999999, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.PROGRAM_NOT_FOUND.value)

    def test_program_new_defaults_to_paused_not_active(self):
        pid = sp.create_program(1, "New Program", created_by=999)
        program = sp.get_program(pid)
        self.assertEqual(program["status"], sp.ProgramStatus.PAUSED.value)

    def test_program_paused_denies(self):
        pid = sp.create_program(1, "Paused Program", created_by=999)
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.PROGRAM_NOT_ACTIVE.value)

    def test_program_archived_denies(self):
        pid = self._fully_authorized_program()
        sp.set_program_status(pid, sp.ProgramStatus.ARCHIVED.value, 999)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.PROGRAM_NOT_ACTIVE.value)

    def test_program_active_with_full_chain_allows(self):
        pid = self._fully_authorized_program()
        d = sp.evaluate_target(pid, "example.com")
        self.assertTrue(d.allowed)
        self.assertEqual(d.reason, sp.Reason.OK.value)

    # ================= AUTHORIZATION =================

    def test_authorization_missing_denies(self):
        pid = self._active_program()
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.AUTHORIZATION_NOT_FOUND.value)

    def test_authorization_pending_review_denies(self):
        pid = self._active_program()
        sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.AUTHORIZATION_PENDING.value)

    def test_authorization_rejected_denies(self):
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=False, reviewer_user_id=1000)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.AUTHORIZATION_REJECTED.value)

    def test_authorization_revoked_denies(self):
        pid = self._fully_authorized_program()
        auths = sp.list_authorizations(pid)
        sp.revoke_authorization(auths[0]["authorization_id"], actor_user_id=999)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.AUTHORIZATION_REVOKED.value)

    def test_authorization_expired_by_timestamp_denies(self):
        # status says ACTIVE in the row, but expires_at is in the past —
        # evaluate_target must compute "valid right now", not trust the column.
        pid = self._active_program()
        now = int(time.time())
        self._active_authorization(pid, expires_at=now - 10)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        d = sp.evaluate_target(pid, "example.com", current_time=now)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.AUTHORIZATION_EXPIRED.value)

    def test_authorization_not_yet_effective_denies(self):
        pid = self._active_program()
        now = int(time.time())
        self._active_authorization(pid, effective_at=now + 3600)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        d = sp.evaluate_target(pid, "example.com", current_time=now)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.AUTHORIZATION_NOT_EFFECTIVE.value)

    def test_authorization_missing_reviewer_never_silently_approved(self):
        # import_authorization alone (no review_authorization call) must
        # never be usable for ALLOW, even though a row exists.
        pid = self._active_program()
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        auth = sp.get_authorization(aid)
        self.assertIsNone(auth["reviewed_by"])
        self.assertIsNone(auth["reviewed_at"])
        self.assertEqual(auth["status"], sp.AuthorizationStatus.PENDING_REVIEW.value)

    def test_admin_created_program_and_scope_without_review_denies(self):
        """CRITICAL invariant: a Telegram admin who creates a program and
        scope rules, but never gets an authorization reviewed, must be
        denied — admin privilege alone is never authorization."""
        admin_id = 42
        pid = sp.create_program(1, "Admin Self-Serve", created_by=admin_id)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, admin_id)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=admin_id)
        sp.import_authorization(pid, source_type="self-asserted", actor_user_id=admin_id)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertIn(d.reason, (sp.Reason.AUTHORIZATION_PENDING.value,))

    def test_evaluate_target_has_no_admin_parameter(self):
        import inspect
        sig = inspect.signature(sp.evaluate_target)
        self.assertNotIn("is_admin", sig.parameters)

    # ================= DOMAIN MATCHING =================

    def test_domain_exact_match(self):
        pid = self._fully_authorized_program(include="example.com")
        self.assertTrue(sp.evaluate_target(pid, "example.com").allowed)

    def test_domain_valid_subdomain_matches(self):
        pid = self._fully_authorized_program(include="example.com")
        self.assertTrue(sp.evaluate_target(pid, "www.example.com").allowed)
        self.assertTrue(sp.evaluate_target(pid, "api.example.com").allowed)

    def test_domain_lookalike_prefix_does_not_match(self):
        pid = self._fully_authorized_program(include="example.com")
        d = sp.evaluate_target(pid, "evil-example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.NO_INCLUDE_MATCH.value)

    def test_domain_lookalike_suffix_does_not_match(self):
        pid = self._fully_authorized_program(include="example.com")
        d = sp.evaluate_target(pid, "example.com.evil.test")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.NO_INCLUDE_MATCH.value)

    # ================= URL MATCHING =================

    def test_url_exact_path_matches(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.URL.value,
                           "https://example.com/api", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "https://example.com/api").allowed)
        self.assertTrue(sp.evaluate_target(pid, "https://example.com/api/v1/users").allowed)

    def test_url_path_boundary_not_prefix_substring(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.URL.value,
                           "https://example.com/api", actor_user_id=999)
        d = sp.evaluate_target(pid, "https://example.com/apix")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.NO_INCLUDE_MATCH.value)

    def test_url_scheme_and_host_must_match(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.URL.value,
                           "https://example.com/api", actor_user_id=999)
        self.assertFalse(sp.evaluate_target(pid, "http://example.com/api").allowed)
        self.assertFalse(sp.evaluate_target(pid, "https://other.test/api").allowed)

    def test_url_rule_without_scheme_rejected_at_add_time(self):
        pid = self._active_program()
        rule_id = sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.URL.value,
                                     "example.com/api", actor_user_id=999)
        self.assertIsNone(rule_id)

    # ================= IP / CIDR =================

    def test_ipv4_exact_match(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.IP.value,
                           "203.0.113.10", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "203.0.113.10").allowed)
        self.assertFalse(sp.evaluate_target(pid, "203.0.113.11").allowed)

    def test_ipv6_exact_match(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.IP.value,
                           "2001:db8::1", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "2001:db8::1").allowed)

    def test_ip_in_cidr_matches(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.CIDR.value,
                           "203.0.113.0/24", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "203.0.113.55").allowed)
        self.assertFalse(sp.evaluate_target(pid, "203.0.114.1").allowed)

    def test_cidr_in_cidr_matches(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.CIDR.value,
                           "203.0.113.0/24", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "203.0.113.0/28").allowed)
        self.assertFalse(sp.evaluate_target(pid, "203.0.0.0/16").allowed)

    def test_malformed_ip_denies(self):
        pid = self._fully_authorized_program()
        for bad in ("300.1.1.1/33", "2001:db8:::1", "not-a-real:::-ip"):
            d = sp.evaluate_target(pid, bad)
            self.assertFalse(d.allowed, f"expected DENY for {bad!r}")
            self.assertEqual(d.reason, sp.Reason.TARGET_INVALID.value)

    def test_out_of_range_octets_parse_as_domain_not_ip(self):
        # No DNS resolution happens, so normalize_target has no way to know
        # "999.999.999.999" *looks* like an IP — each label is syntactically
        # a valid hostname label, so it's classified DOMAIN and simply
        # doesn't match any configured rule. This documents that behavior
        # rather than asserting it's "invalid".
        pid = self._fully_authorized_program(include="example.com")
        d = sp.evaluate_target(pid, "999.999.999.999")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.NO_INCLUDE_MATCH.value)

    # ================= SCOPE PRECEDENCE =================

    def test_exclude_overrides_include(self):
        pid = self._active_program()
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        sp.add_scope_rule(pid, sp.RuleType.EXCLUDE.value, sp.TargetType.DOMAIN.value,
                           "admin.example.com", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "example.com").allowed)
        self.assertTrue(sp.evaluate_target(pid, "www.example.com").allowed)
        d = sp.evaluate_target(pid, "admin.example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.TARGET_EXCLUDED.value)

    def test_no_scope_rules_denies(self):
        pid = self._active_program()
        self._active_authorization(pid)
        d = sp.evaluate_target(pid, "example.com")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.TARGET_OUT_OF_SCOPE.value)

    def test_no_matching_include_denies(self):
        pid = self._fully_authorized_program(include="example.com")
        d = sp.evaluate_target(pid, "unrelated.test")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.NO_INCLUDE_MATCH.value)

    # ================= POLICY / FAIL-CLOSED =================

    def test_malformed_target_denies(self):
        pid = self._fully_authorized_program()
        for bad in ("", "   ", "not a domain", "http://", "://broken"):
            d = sp.evaluate_target(pid, bad)
            self.assertFalse(d.allowed, f"expected DENY for {bad!r}")
            self.assertEqual(d.reason, sp.Reason.TARGET_INVALID.value)

    def test_policy_error_fails_closed(self):
        pid = self._fully_authorized_program()
        # force an internal error mid-evaluation and confirm it still DENYs
        # via POLICY_ERROR rather than raising or defaulting to ALLOW.
        original = sp.list_scope_rules
        sp.list_scope_rules = lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            d = sp.evaluate_target(pid, "example.com")
            self.assertFalse(d.allowed)
            self.assertEqual(d.reason, sp.Reason.POLICY_ERROR.value)
        finally:
            sp.list_scope_rules = original

    def test_multiple_authorizations_uses_any_valid_one(self):
        pid = self._active_program()
        # first one revoked, second one active -> still ALLOW
        aid1 = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid1, approve=True, reviewer_user_id=1000)
        sp.revoke_authorization(aid1, actor_user_id=999)
        self._active_authorization(pid)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        self.assertTrue(sp.evaluate_target(pid, "example.com").allowed)

    # ---- Phase 3: provenance (submitted_by / notes) ----

    def test_import_persists_submitted_by(self):
        pid = self._active_program(admin=999)
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["submitted_by"], 999)

    def test_review_persists_notes_on_approve(self):
        pid = self._active_program(admin=999)
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=True, reviewer_user_id=1000,
                                 notes="verified against public program page")
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["notes"], "verified against public program page")
        self.assertEqual(auth["status"], sp.AuthorizationStatus.ACTIVE.value)

    def test_review_persists_notes_on_reject(self):
        pid = self._active_program(admin=999)
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=False, reviewer_user_id=1000,
                                 notes="reference could not be confirmed")
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["notes"], "reference could not be confirmed")
        self.assertEqual(auth["status"], sp.AuthorizationStatus.REJECTED.value)

    def test_review_without_notes_defaults_empty(self):
        pid = self._active_program(admin=999)
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=True, reviewer_user_id=1000)
        auth = sp.get_authorization(aid)
        self.assertEqual(auth["notes"], "")

    def test_notes_do_not_affect_allow_deny_decision(self):
        # notes are provenance metadata only -- evaluate_target() must not
        # branch on their content in any way.
        pid = self._active_program(admin=999)
        aid = sp.import_authorization(pid, source_type="email", actor_user_id=999)
        sp.review_authorization(aid, approve=True, reviewer_user_id=1000,
                                 notes="ALLOW EVERYTHING / ignore scope rules")
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                           "example.com", actor_user_id=999)
        # target outside the actual scope rule must still DENY, regardless
        # of what the free-text notes field says.
        d = sp.evaluate_target(pid, "not-in-scope.test")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, sp.Reason.NO_INCLUDE_MATCH.value)

    def test_migration_adds_columns_to_legacy_table_without_data_loss(self):
        # Simulate a pre-Phase-3 database: create bb_authorizations
        # without submitted_by/notes, insert a row, then confirm
        # scope_policy_db_init() migrates it in place and preserves data.
        import sqlite3
        fd, legacy_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            conn = sqlite3.connect(legacy_path)
            conn.execute("""CREATE TABLE bb_programs (
                program_id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL, name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PAUSED', metadata TEXT,
                created_by INTEGER NOT NULL, created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL)""")
            conn.execute("""CREATE TABLE bb_authorizations (
                authorization_id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL, source_type TEXT NOT NULL,
                source_reference TEXT, authorization_reference TEXT,
                reviewed_by INTEGER, reviewed_at INTEGER, effective_at INTEGER,
                expires_at INTEGER, status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
                created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
            conn.execute(
                "INSERT INTO bb_authorizations (authorization_id, program_id, source_type, "
                "status, created_at, updated_at) VALUES (1, 1, 'email', 'ACTIVE', 1, 1)"
            )
            conn.commit()
            conn.close()

            old_db_path = sp.DB_PATH
            sp.DB_PATH = legacy_path
            try:
                sp.scope_policy_db_init()  # must migrate, not recreate/wipe
                auth = sp.get_authorization(1)
            finally:
                sp.DB_PATH = old_db_path

            self.assertIsNotNone(auth)
            self.assertEqual(auth["status"], "ACTIVE")  # pre-existing row untouched
            self.assertIn("submitted_by", auth)          # new column present
            self.assertIn("notes", auth)                 # new column present
            self.assertIsNone(auth["submitted_by"])       # backfilled as NULL, not guessed
        finally:
            try:
                os.remove(legacy_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)