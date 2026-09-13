"""
test_bb_scan.py — Phase 10 test suite (authorized scan campaigns).

Same isolation pattern as test_security_testing.py: a fresh temp SQLite
file per test; Programs/Authorizations/Scope built through
scope_policy.py's real API; Findings created through findings.py's real
API. The network layer (security_testing.run_security_check) is mocked,
so no test resolves a hostname or opens a socket -- bb_scan never touches
the network itself, which these tests also assert via a tripwire.

Coverage emphasis (the properties that matter for a scanner built on the
BB stack):
  - authorization is decided BEFORE any check runs; a denied target runs
    zero checks and is still recorded (auditable attempt).
  - the SSRF guard / rate limiter / gate inside run_security_check are
    reused, never re-implemented or weakened.
  - promotion to a Finding re-gates through the CURRENT scope, so a
    lapsed authorization blocks it even for an earlier in-scope scan.
  - promotion never silently duplicates, never inflates severity.
"""

import os
import asyncio
import sqlite3
import tempfile
import unittest
from unittest import mock

import security
import scope_policy as sp
import findings as fnd
import security_testing as st
import bb_scan


class _Tripwire(Exception):
    """Raised by a stub that must never be reached."""


def _check_result(check_type, status="COMPLETED", reason="OK", target="example.com",
                  observations=None):
    """Canned run_security_check() return dict, matching CheckResult.as_dict()."""
    return {
        "ok": status == "COMPLETED",
        "status": status,
        "reason": reason,
        "program_id": 1,
        "target": target,
        "check_type": check_type,
        "findings": observations or [],
        "data": {},
    }


def _obs(severity_hint, code, detail=""):
    return {"severity_hint": severity_hint, "code": code, "detail": detail}


class BBScanTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db = path
        for m in (security, sp, fnd, st, bb_scan):
            m.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()
        fnd.findings_db_init()
        st.security_testing_db_init()
        bb_scan.bb_scan_db_init()

    def tearDown(self):
        try:
            os.remove(self._db)
        except OSError:
            pass

    # ---- fixtures ----

    def _authorized_program(self, include="example.com", chat_id=1, admin=999):
        pid = sp.create_program(chat_id, "Acme BB", created_by=admin)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, admin)
        aid = sp.import_authorization(
            pid, source_type="email", actor_user_id=admin,
            source_reference="security@acme.test", authorization_reference="REF-1")
        sp.review_authorization(aid, approve=True, reviewer_user_id=1000)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                          include, actor_user_id=admin)
        return pid

    def _mock_checks(self, mapping):
        """Patch bb_scan.run_security_check so each check_type returns a
        canned dict from `mapping` (check_type -> result dict)."""
        async def fake(program_id, target, check_type, actor):
            return mapping.get(check_type,
                               _check_result(check_type, status="FAILED",
                                             reason="REQUEST_FAILED"))
        return mock.patch.object(bb_scan, "run_security_check", fake)

    def _tripwire_checks(self):
        async def boom(program_id, target, check_type, actor):
            raise _Tripwire(f"run_security_check should not run: {check_type}")
        return mock.patch.object(bb_scan, "run_security_check", boom)


# ---------------- DB init ----------------

class DatabaseInitTests(BBScanTestCase):
    async def test_tables_created(self):
        conn = sqlite3.connect(self._db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        for t in ("bb_scans", "bb_scan_checks", "bb_scan_observations"):
            self.assertIn(t, tables)

    async def test_init_idempotent_and_preserves_rows(self):
        pid = self._authorized_program()
        with self._mock_checks({"headers": _check_result("headers")}):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        bb_scan.bb_scan_db_init()
        self.assertIsNotNone(bb_scan.get_scan(r["scan_id"]))

    async def test_profiles_only_reference_real_checks(self):
        for name, checks in bb_scan.SCAN_PROFILES.items():
            for c in checks:
                self.assertIn(c, st.VALID_CHECK_TYPES,
                              f"profile {name} references unknown check {c}")


# ---------------- Input validation ----------------

class InputValidationTests(BBScanTestCase):
    async def test_unknown_profile_denied_without_running_checks(self):
        pid = self._authorized_program()
        with self._tripwire_checks():
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="aggressive")
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "UNKNOWN_PROFILE")

    async def test_invalid_program_id(self):
        r = await bb_scan.run_scan(0, "example.com", 42)
        self.assertEqual(r["reason"], "INVALID_PROGRAM_ID")

    async def test_invalid_actor(self):
        pid = self._authorized_program()
        r = await bb_scan.run_scan(pid, "example.com", 0)
        self.assertEqual(r["reason"], "INVALID_ACTOR")

    async def test_bool_is_not_a_valid_program_id(self):
        r = await bb_scan.run_scan(True, "example.com", 42)
        self.assertEqual(r["reason"], "INVALID_PROGRAM_ID")

    async def test_blank_target(self):
        pid = self._authorized_program()
        r = await bb_scan.run_scan(pid, "   ", 42)
        self.assertEqual(r["reason"], "TARGET_INVALID")


# ---------------- Authorization gate ----------------

class AuthorizationGateTests(BBScanTestCase):
    async def test_out_of_scope_denied_runs_no_check(self):
        pid = self._authorized_program(include="example.com")
        with self._tripwire_checks():
            r = await bb_scan.run_scan(pid, "not-in-scope.com", 42, profile="full")
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], bb_scan.SCAN_DENIED)
        # denial is persisted for audit, with no observations
        scan = bb_scan.get_scan(r["scan_id"])
        self.assertEqual(scan["status"], "DENIED")
        self.assertEqual(scan["checks_completed"], 0)
        self.assertEqual(bb_scan.list_observations(r["scan_id"]), [])

    async def test_paused_program_denied(self):
        pid = self._authorized_program()
        sp.set_program_status(pid, sp.ProgramStatus.PAUSED.value, 999)
        with self._tripwire_checks():
            r = await bb_scan.run_scan(pid, "example.com", 42)
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], bb_scan.SCAN_DENIED)

    async def test_unknown_program_denied(self):
        with self._tripwire_checks():
            r = await bb_scan.run_scan(4242, "example.com", 42)
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], bb_scan.SCAN_DENIED)

    async def test_denied_scan_writes_audit(self):
        pid = self._authorized_program(include="example.com")
        with self._tripwire_checks():
            await bb_scan.run_scan(pid, "evil.com", 42)
        actions = [a["action"] for a in security.get_recent_audit_log(1, limit=20)]
        self.assertIn("SCAN_DENIED", actions)

    async def test_has_no_is_admin_parameter(self):
        import inspect
        self.assertNotIn("is_admin", inspect.signature(bb_scan.run_scan).parameters)


# ---------------- Orchestration & aggregation ----------------

class OrchestrationTests(BBScanTestCase):
    async def test_full_scan_aggregates_and_persists(self):
        pid = self._authorized_program()
        mapping = {
            "headers": _check_result("headers", observations=[
                _obs("LOW", "MISSING_SECURITY_HEADER", "Content-Security-Policy"),
                _obs("INFO", "VERSION_DISCLOSURE", "Server: nginx"),
            ]),
            "tls": _check_result("tls", observations=[
                _obs("MEDIUM", "TLS_OBSOLETE_VERSION", "TLSv1.1")]),
            "cookies": _check_result("cookies"),
            "redirects": _check_result("redirects"),
            "cors": _check_result("cors"),
            "technology": _check_result("technology"),
        }
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="full")
        self.assertTrue(r["ok"])
        self.assertEqual(r["status"], bb_scan.SCAN_COMPLETED)
        scan = bb_scan.get_scan(r["scan_id"])
        self.assertEqual(scan["checks_requested"], 6)
        self.assertEqual(scan["checks_completed"], 6)
        self.assertEqual(scan["medium_count"], 1)
        self.assertEqual(scan["low_count"], 1)
        self.assertEqual(scan["info_count"], 1)
        self.assertEqual(scan["grade"], "C")  # a MEDIUM present
        obs = bb_scan.list_observations(r["scan_id"])
        self.assertEqual(len(obs), 3)
        self.assertEqual([o["idx"] for o in obs], [1, 2, 3])  # 1-based, contiguous

    async def test_quick_profile_runs_three_checks(self):
        pid = self._authorized_program()
        seen = []
        async def fake(program_id, target, check_type, actor):
            seen.append(check_type)
            return _check_result(check_type)
        with mock.patch.object(bb_scan, "run_security_check", fake):
            await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        self.assertEqual(set(seen), {"headers", "cookies", "tls"})

    async def test_per_check_coverage_is_recorded(self):
        pid = self._authorized_program()
        mapping = {
            "headers": _check_result("headers"),
            "tls": _check_result("tls", status="FAILED", reason="TLS_TIMEOUT"),
            "cookies": _check_result("cookies"),
        }
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        checks = {c["check_type"]: c for c in bb_scan.list_scan_checks(r["scan_id"])}
        self.assertEqual(checks["tls"]["status"], "FAILED")
        self.assertEqual(checks["tls"]["reason"], "TLS_TIMEOUT")
        self.assertEqual(checks["headers"]["status"], "COMPLETED")
        scan = bb_scan.get_scan(r["scan_id"])
        self.assertEqual(scan["checks_completed"], 2)
        self.assertEqual(scan["checks_failed"], 1)

    async def test_grade_a_when_only_info_or_none(self):
        pid = self._authorized_program()
        mapping = {"headers": _check_result("headers", observations=[
            _obs("INFO", "VERSION_DISCLOSURE", "x")]),
            "cookies": _check_result("cookies"), "tls": _check_result("tls")}
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        self.assertEqual(bb_scan.get_scan(r["scan_id"])["grade"], "A")

    async def test_grade_b_when_low_is_worst(self):
        pid = self._authorized_program()
        mapping = {"headers": _check_result("headers", observations=[
            _obs("LOW", "MISSING_SECURITY_HEADER", "x")]),
            "cookies": _check_result("cookies"), "tls": _check_result("tls")}
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        self.assertEqual(bb_scan.get_scan(r["scan_id"])["grade"], "B")

    async def test_all_checks_rate_limited_is_failed_not_completed(self):
        pid = self._authorized_program()
        mapping = {c: _check_result(c, status="DENIED", reason="RATE_LIMIT_TARGET")
                   for c in ("headers", "cookies", "tls")}
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        self.assertFalse(r["ok"])
        self.assertEqual(r["status"], bb_scan.SCAN_FAILED)
        self.assertEqual(r["reason"], "NO_CHECK_COMPLETED")
        self.assertEqual(bb_scan.get_scan(r["scan_id"])["grade"], "N/A")

    async def test_completed_scan_writes_audit(self):
        pid = self._authorized_program()
        with self._mock_checks({"headers": _check_result("headers"),
                                "cookies": _check_result("cookies"),
                                "tls": _check_result("tls")}):
            await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        actions = [a["action"] for a in security.get_recent_audit_log(1, limit=20)]
        self.assertIn("SCAN_REQUESTED", actions)
        self.assertIn("SCAN_COMPLETED", actions)

    async def test_scan_history_lists_newest_first(self):
        pid = self._authorized_program()
        with self._mock_checks({"headers": _check_result("headers"),
                                "cookies": _check_result("cookies"),
                                "tls": _check_result("tls")}):
            r1 = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
            r2 = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        scans = bb_scan.list_scans(pid)
        self.assertEqual([s["scan_id"] for s in scans[:2]], [r2["scan_id"], r1["scan_id"]])


# ---------------- Promotion bridge ----------------

class PromotionTests(BBScanTestCase):
    async def _scan_with_observation(self, pid, hint="MEDIUM"):
        mapping = {"headers": _check_result("headers", observations=[
            _obs(hint, "MISSING_SECURITY_HEADER", "Content-Security-Policy")]),
            "cookies": _check_result("cookies"), "tls": _check_result("tls")}
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        return r["scan_id"]

    async def test_promote_creates_finding_and_evidence(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid, hint="MEDIUM")
        result = bb_scan.promote_observation(scan_id, 1, actor=42)
        self.assertTrue(result["ok"], result.get("reason"))
        self.assertIsNotNone(result["finding_id"])
        # the Finding really exists, in scope, with the mapped severity
        finding = fnd.get_finding(result["finding_id"])
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["target"], "example.com")
        self.assertEqual(finding["status"], "OPEN")
        # detail attached as evidence
        self.assertIsNotNone(result["evidence_id"])
        self.assertEqual(len(fnd.list_evidence(result["finding_id"])), 1)

    async def test_promote_stamps_observation_and_blocks_double(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid)
        first = bb_scan.promote_observation(scan_id, 1, actor=42)
        again = bb_scan.promote_observation(scan_id, 1, actor=42)
        self.assertFalse(again["ok"])
        self.assertEqual(again["reason"], "ALREADY_PROMOTED")
        self.assertEqual(again["finding_id"], first["finding_id"])
        # only one Finding was created
        self.assertEqual(len(fnd.list_findings(pid)), 1)

    async def test_promote_default_severity_is_faithful_map(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid, hint="LOW")
        result = bb_scan.promote_observation(scan_id, 1, actor=42)
        self.assertEqual(fnd.get_finding(result["finding_id"])["severity"], "LOW")

    async def test_promote_severity_override(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid, hint="LOW")
        result = bb_scan.promote_observation(scan_id, 1, actor=42, severity="HIGH")
        self.assertEqual(fnd.get_finding(result["finding_id"])["severity"], "HIGH")

    async def test_promote_invalid_severity_rejected(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid)
        result = bb_scan.promote_observation(scan_id, 1, actor=42, severity="APOCALYPSE")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "INVALID_SEVERITY")
        self.assertEqual(len(fnd.list_findings(pid)), 0)

    async def test_promote_custom_title(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid)
        result = bb_scan.promote_observation(scan_id, 1, actor=42,
                                             title="CSP header missing on login")
        self.assertEqual(fnd.get_finding(result["finding_id"])["title"],
                         "CSP header missing on login")

    async def test_promotion_re_gates_through_current_scope(self):
        """The core safety property of the bridge: even though the scan
        ran while in scope, if the authorization is later revoked the
        promotion must be refused -- create_finding re-runs the gate."""
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid)
        # revoke every authorization on the program
        for a in sp.list_authorizations(pid):
            sp.revoke_authorization(a["authorization_id"], actor_user_id=999)
        result = bb_scan.promote_observation(scan_id, 1, actor=42)
        self.assertFalse(result["ok"])
        self.assertEqual(len(fnd.list_findings(pid)), 0)
        # observation stays un-promoted, so it can be promoted later if
        # authorization is restored
        self.assertIsNone(bb_scan.get_observation(scan_id, 1)["promoted_finding_id"])

    async def test_promote_unknown_scan_or_observation(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid)
        self.assertEqual(bb_scan.promote_observation(9999, 1, actor=42)["reason"],
                         "SCAN_NOT_FOUND")
        self.assertEqual(bb_scan.promote_observation(scan_id, 99, actor=42)["reason"],
                         "OBSERVATION_NOT_FOUND")

    async def test_promote_invalid_actor(self):
        pid = self._authorized_program()
        scan_id = await self._scan_with_observation(pid)
        self.assertEqual(bb_scan.promote_observation(scan_id, 1, actor=0)["reason"],
                         "INVALID_ACTOR")


# ---------------- Presentation ----------------

class PresentationTests(BBScanTestCase):
    async def test_report_lists_indexed_observations_and_disclaimer(self):
        pid = self._authorized_program()
        mapping = {"headers": _check_result("headers", observations=[
            _obs("MEDIUM", "TLS_OBSOLETE_VERSION", "TLSv1.1")]),
            "cookies": _check_result("cookies"), "tls": _check_result("tls")}
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        text = bb_scan.format_scan_report(bb_scan.get_scan_bundle(r["scan_id"]))
        self.assertIn("รายงานการสแกน", text)
        self.assertIn("/scanpromote", text)
        self.assertIn("1.", text)  # indexed observation
        self.assertIn(bb_scan.SCAN_DISCLAIMER[:20], text)

    async def test_denied_result_renders_reason(self):
        pid = self._authorized_program(include="example.com")
        with self._tripwire_checks():
            r = await bb_scan.run_scan(pid, "evil.com", 42)
        self.assertIn("❌", bb_scan.format_scan_result(r))

    async def test_scan_list_render(self):
        pid = self._authorized_program()
        with self._mock_checks({"headers": _check_result("headers"),
                                "cookies": _check_result("cookies"),
                                "tls": _check_result("tls")}):
            await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        text = bb_scan.format_scan_list(pid, bb_scan.list_scans(pid))
        self.assertIn("ประวัติการสแกน", text)
        self.assertIn("example.com", text)

    async def test_promote_result_render(self):
        pid = self._authorized_program()
        mapping = {"headers": _check_result("headers", observations=[
            _obs("MEDIUM", "X", "y")]), "cookies": _check_result("cookies"),
            "tls": _check_result("tls")}
        with self._mock_checks(mapping):
            r = await bb_scan.run_scan(pid, "example.com", 42, profile="quick")
        promoted = bb_scan.promote_observation(r["scan_id"], 1, actor=42)
        self.assertIn("Finding", bb_scan.format_promote_result(promoted))


if __name__ == "__main__":
    unittest.main()
