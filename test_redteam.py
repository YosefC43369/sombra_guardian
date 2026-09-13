"""
test_redteam.py — Phase 11 test suite (Red Team Assessment).

Same isolation pattern as the other suites: a fresh temp SQLite file per
test; scope built through scope_policy.py's real API; every RoE decision
made by the real redteam.check_roe()/scope_policy.evaluate_target().

Emphasis on the safety-critical properties:
  - the RoE gate denies by default and blocks out-of-scope / unauthorized
    operator / closed window / kill-switched / pre-authorization access,
  - a finding can never reach VERIFIED_RISK without a human action AND
    attached evidence (no auto-promotion),
  - evidence SHA-256 integrity detects tampering,
  - PII is scrubbed from stored evidence,
  - the audit trail and append-only custody record every action,
  - a registered target must have passed the RoE gate.
"""

import os
import json
import sqlite3
import tempfile
import unittest

import security
import scope_policy as sp
import redteam as rt
import redteam_report as rr

T = 1_700_000_000
CHAT = -100
LEAD = 900
OP = 901
OUTSIDER = 700


class RedTeamTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db = path
        for m in (security, sp, rt):
            m.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()
        rt.redteam_db_init()

    def tearDown(self):
        try:
            os.remove(self._db)
        except OSError:
            pass

    # ---- fixtures ----

    def _engagement(self, authorize=True, include="acme.test", limited=False,
                    window_end=None, expires_at=None, add_op=True):
        e = rt.create_engagement(CHAT, "Acme Pentest", created_by=LEAD)
        eid = e.id
        if add_op:
            rt.add_operator(eid, OP, actor_id=LEAD)
        rt.add_scope(eid, "INCLUDE", "DOMAIN", include, actor_id=LEAD)
        if authorize:
            rt.authorize_engagement(eid, approver_id=LEAD, roe_reference="SOW-1",
                                    window_end=window_end, expires_at=expires_at,
                                    limited=limited, now=T)
        return eid

    def _finding(self, eid, cls="EXPOSURE", severity="HIGH", confidence="MEDIUM"):
        return rt.create_finding(eid, "Exposed admin panel", operator_id=OP,
                                 classification=cls, severity=severity,
                                 confidence=confidence, now=T + 5).id


# ---------------- DB init (Phase 23) ----------------

class DatabaseInitTests(RedTeamTestCase):
    def test_all_tables_created(self):
        conn = sqlite3.connect(self._db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        for t in ("rt_engagements", "rt_operators", "rt_targets", "rt_findings",
                  "rt_evidence", "rt_custody", "rt_timeline", "rt_vectors",
                  "rt_review_queue", "rt_defense_checks", "rt_ai_analysis"):
            self.assertIn(t, tables)

    def test_init_idempotent_and_preserves_rows(self):
        eid = self._engagement()
        for _ in range(3):
            rt.redteam_db_init()
        self.assertIsNotNone(rt.get_engagement(eid))

    def test_custody_module_is_append_only(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "redteam.py"), encoding="utf-8") as fh:
            src = fh.read().lower()
        self.assertNotIn("delete from rt_custody", src)
        self.assertNotIn("update rt_custody", src)


# ---------------- Phase 1/2: engagement + RoE gate ----------------

class EngagementRoeTests(RedTeamTestCase):
    def test_new_engagement_is_pending_and_backed_by_program(self):
        e = rt.create_engagement(CHAT, "Test", created_by=LEAD)
        self.assertTrue(e.ok)
        eng = rt.get_engagement(e.id)
        self.assertEqual(eng["status"], "PENDING_APPROVAL")
        self.assertIsNotNone(sp.get_program(eng["program_id"]))

    def test_pending_engagement_denies_everything(self):
        eid = self._engagement(authorize=False)
        d = rt.check_roe(eid, "acme.test", OP, now=T)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stage, "STATUS")

    def test_authorize_requires_roe_reference(self):
        eid = self._engagement(authorize=False)
        r = rt.authorize_engagement(eid, approver_id=LEAD, roe_reference="  ", now=T)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "ROE_REFERENCE_REQUIRED")

    def test_authorized_in_scope_target_allowed(self):
        eid = self._engagement()
        d = rt.check_roe(eid, "acme.test", OP, now=T + 10)
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(d.stage, "ALLOW")

    def test_out_of_scope_target_denied(self):
        eid = self._engagement(include="acme.test")
        d = rt.check_roe(eid, "not-mine.test", OP, now=T + 10)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stage, "SCOPE")

    def test_unauthorized_operator_denied(self):
        eid = self._engagement()
        d = rt.check_roe(eid, "acme.test", OUTSIDER, now=T + 10)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stage, "OPERATOR")

    def test_window_not_open_denied(self):
        eid = self._engagement()
        # move window_start into the future
        conn = sqlite3.connect(self._db)
        conn.execute("UPDATE rt_engagements SET window_start=? WHERE engagement_id=?",
                     (T + 10_000, eid))
        conn.commit()
        conn.close()
        d = rt.check_roe(eid, "acme.test", OP, now=T + 10)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stage, "WINDOW")

    def test_window_closed_denied(self):
        eid = self._engagement(window_end=T + 100)
        d = rt.check_roe(eid, "acme.test", OP, now=T + 5000)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stage, "WINDOW")

    def test_expired_engagement_denied(self):
        eid = self._engagement(expires_at=T + 100)
        d = rt.check_roe(eid, "acme.test", OP, now=T + 5000)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "ENGAGEMENT_EXPIRED")

    def test_kill_switch_denies_and_is_terminal(self):
        eid = self._engagement()
        rt.trigger_kill_switch(eid, actor_id=LEAD, reason="client stop", now=T + 20)
        d = rt.check_roe(eid, "acme.test", OP, now=T + 30)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stage, "KILL_SWITCH")
        # terminal: cannot transition back
        r = rt.set_engagement_status(eid, "AUTHORIZED", actor_id=LEAD, now=T + 40)
        self.assertFalse(r.ok)

    def test_kill_switch_revokes_backing_authorization(self):
        eid = self._engagement()
        rt.trigger_kill_switch(eid, actor_id=LEAD, now=T + 20)
        eng = rt.get_engagement(eid)
        # even bypassing the engagement layer, scope_policy now denies
        self.assertFalse(sp.evaluate_target(eng["program_id"], "acme.test").allowed)

    def test_limited_scope_is_operational(self):
        eid = self._engagement(limited=True)
        self.assertEqual(rt.get_engagement(eid)["status"], "LIMITED_SCOPE")
        self.assertTrue(rt.check_roe(eid, "acme.test", OP, now=T + 10).allowed)

    def test_paused_engagement_denied_then_resumable(self):
        eid = self._engagement()
        rt.set_engagement_status(eid, "PAUSED", actor_id=LEAD, now=T + 10)
        self.assertFalse(rt.check_roe(eid, "acme.test", OP, now=T + 11).allowed)
        rt.set_engagement_status(eid, "AUTHORIZED", actor_id=LEAD, now=T + 12)
        self.assertTrue(rt.check_roe(eid, "acme.test", OP, now=T + 13).allowed)

    def test_roe_gate_has_no_is_admin_parameter(self):
        import inspect
        self.assertNotIn("is_admin", inspect.signature(rt.check_roe).parameters)

    def test_unknown_engagement_denied(self):
        d = rt.check_roe(99999, "acme.test", OP, now=T)
        self.assertFalse(d.allowed)
        self.assertEqual(d.stage, "ENGAGEMENT")


# ---------------- Phase 3/7: target registry ----------------

class TargetRegistryTests(RedTeamTestCase):
    def test_in_scope_target_registers(self):
        eid = self._engagement()
        r = rt.register_target(eid, "acme.test", "EXTERNAL_PERIMETER", operator_id=OP, now=T + 10)
        self.assertTrue(r.ok, r.reason)
        self.assertEqual(r.detail, "IN_SCOPE")

    def test_out_of_scope_target_refused(self):
        eid = self._engagement(include="acme.test")
        r = rt.register_target(eid, "evil.test", "EXTERNAL_PERIMETER", operator_id=OP, now=T + 10)
        self.assertFalse(r.ok)
        self.assertEqual(len(rt.list_targets(eid)), 0)

    def test_out_of_scope_registration_is_audited(self):
        eid = self._engagement(include="acme.test")
        rt.register_target(eid, "evil.test", "EXTERNAL_PERIMETER", operator_id=OP, now=T + 10)
        actions = [a["action"] for a in security.get_recent_audit_log(CHAT, limit=30)]
        self.assertIn("RT_TARGET_REGISTER_DENIED", actions)

    def test_unauthorized_operator_cannot_register(self):
        eid = self._engagement()
        r = rt.register_target(eid, "acme.test", "EXTERNAL_PERIMETER", operator_id=OUTSIDER,
                               now=T + 10)
        self.assertFalse(r.ok)

    def test_invalid_category_refused(self):
        eid = self._engagement()
        r = rt.register_target(eid, "acme.test", "MADE_UP", operator_id=OP, now=T + 10)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "INVALID_CATEGORY")

    def test_simulated_vector_skips_network_scope_but_needs_operational(self):
        eid = self._engagement()
        r = rt.register_target(eid, "APT29 phishing lure", "SIMULATED_THREAT_VECTOR",
                               operator_id=OP, now=T + 10)
        self.assertTrue(r.ok)
        self.assertEqual(r.detail, "SIMULATED")

    def test_simulated_vector_still_denied_when_not_operational(self):
        eid = self._engagement(authorize=False)
        r = rt.register_target(eid, "lure", "SIMULATED_THREAT_VECTOR", operator_id=OP, now=T + 10)
        self.assertFalse(r.ok)


# ---------------- Phase 5/6/14: findings + no auto-promote ----------------

class FindingClassificationTests(RedTeamTestCase):
    def test_create_lead_and_exposure(self):
        eid = self._engagement()
        self.assertTrue(rt.create_finding(eid, "t", operator_id=OP, classification="LEAD",
                                          severity="LOW", confidence="LOW", now=T + 5).ok)
        self.assertTrue(rt.create_finding(eid, "t2", operator_id=OP, classification="EXPOSURE",
                                          severity="MEDIUM", confidence="MEDIUM", now=T + 5).ok)

    def test_cannot_create_verified_risk_directly(self):
        eid = self._engagement()
        r = rt.create_finding(eid, "cheat", operator_id=OP, classification="VERIFIED_RISK",
                              severity="CRITICAL", confidence="HIGH", now=T + 5)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "VERIFIED_RISK_REQUIRES_REVIEW")

    def test_cannot_promote_to_verified_risk_without_evidence(self):
        eid = self._engagement()
        fid = self._finding(eid)
        r = rt.reclassify_finding(fid, "VERIFIED_RISK", operator_id=OP, now=T + 6)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "EVIDENCE_REQUIRED")
        self.assertEqual(rt.get_finding(fid)["classification"], "EXPOSURE")

    def test_can_promote_to_verified_risk_with_evidence(self):
        eid = self._engagement()
        fid = self._finding(eid)
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, finding_id=fid,
                        raw_content="200 OK proof", now=T + 6)
        r = rt.reclassify_finding(fid, "VERIFIED_RISK", operator_id=OP, now=T + 7)
        self.assertTrue(r.ok, r.reason)
        f = rt.get_finding(fid)
        self.assertEqual(f["classification"], "VERIFIED_RISK")
        self.assertEqual(f["reviewed_by"], OP)

    def test_review_confirm_promotes_only_with_evidence(self):
        eid = self._engagement()
        fid = self._finding(eid)  # enqueues a review item
        item = rt.list_review_queue(eid)[0]
        # confirm without evidence -> blocked by the same rule
        r = rt.decide_review(item["item_id"], "CONFIRMED", operator_id=LEAD, now=T + 6)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "EVIDENCE_REQUIRED")
        # add evidence, then confirm -> promotes
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, finding_id=fid,
                        raw_content="proof", now=T + 7)
        r2 = rt.decide_review(item["item_id"], "CONFIRMED", operator_id=LEAD, now=T + 8)
        self.assertTrue(r2.ok, r2.reason)
        self.assertEqual(rt.get_finding(fid)["classification"], "VERIFIED_RISK")

    def test_dismiss_review_item(self):
        eid = self._engagement()
        self._finding(eid)
        item = rt.list_review_queue(eid)[0]
        r = rt.decide_review(item["item_id"], "DISMISSED", operator_id=LEAD, now=T + 6)
        self.assertTrue(r.ok)
        self.assertEqual(rt.list_review_queue(eid, status="DISMISSED")[0]["item_id"],
                         item["item_id"])

    def test_severity_and_confidence_validated(self):
        eid = self._engagement()
        self.assertEqual(rt.create_finding(eid, "t", operator_id=OP, severity="OMG",
                                           confidence="LOW", now=T + 5).reason,
                         "INVALID_SEVERITY")
        self.assertEqual(rt.create_finding(eid, "t", operator_id=OP, severity="LOW",
                                           confidence="SURE", now=T + 5).reason,
                         "INVALID_CONFIDENCE")

    def test_finding_severity_rationale_is_stored(self):
        eid = self._engagement()
        fid = self._finding(eid, severity="HIGH", confidence="MEDIUM")
        self.assertTrue(rt.get_finding(fid)["severity_rationale"])

    def test_risk_score_is_explainable_and_bounded(self):
        self.assertEqual(rt.compute_risk_score("CRITICAL", "HIGH"), 90)
        self.assertLess(rt.compute_risk_score("HIGH", "LOW"),
                        rt.compute_risk_score("HIGH", "HIGH"))
        self.assertLess(rt.compute_risk_score("HIGH", "HIGH", compensating_controls=True),
                        rt.compute_risk_score("HIGH", "HIGH"))


# ---------------- Phase 8: vectors ----------------

class VectorTests(RedTeamTestCase):
    def test_vector_starts_unverified_and_cannot_be_born_confirmed(self):
        eid = self._engagement()
        r = rt.create_vector(eid, "DA via Kerberoast", operator_id=OP, now=T + 5)
        self.assertEqual(rt.get_vector(r.id)["status"], "UNVERIFIED")

    def test_vector_confirmed_only_by_review(self):
        eid = self._engagement()
        vid = rt.create_vector(eid, "path", operator_id=OP, now=T + 5).id
        r = rt.review_vector(vid, "CONFIRMED", operator_id=LEAD, confidence="HIGH", now=T + 6)
        self.assertTrue(r.ok)
        self.assertEqual(rt.get_vector(vid)["status"], "CONFIRMED")


# ---------------- Phase 4/16/17: evidence + integrity + PII ----------------

class EvidenceIntegrityTests(RedTeamTestCase):
    def test_evidence_has_sha256_and_verifies(self):
        eid = self._engagement()
        r = rt.add_evidence(eid, "COMMAND_LOG", operator_id=OP, raw_content="nmap output",
                            now=T + 5)
        self.assertTrue(r.ok)
        self.assertEqual(len(r.detail), 64)
        v = rt.verify_evidence(r.id, operator_id=OP, now=T + 6)
        self.assertTrue(v.match)

    def test_tampered_evidence_fails_verification(self):
        eid = self._engagement()
        r = rt.add_evidence(eid, "COMMAND_LOG", operator_id=OP, raw_content="orig", now=T + 5)
        conn = sqlite3.connect(self._db)
        conn.execute("UPDATE rt_evidence SET raw_content='tampered' WHERE evidence_id=?", (r.id,))
        conn.commit()
        conn.close()
        v = rt.verify_evidence(r.id, operator_id=OP, now=T + 6)
        self.assertTrue(v.ok)
        self.assertFalse(v.match)
        self.assertEqual(rt.get_evidence(r.id)["last_verify_result"], "FAILED")

    def test_verifying_does_not_change_hash(self):
        eid = self._engagement()
        r = rt.add_evidence(eid, "RESPONSE", operator_id=OP, raw_content="x", now=T + 5)
        self.assertTrue(rt.verify_evidence(r.id, now=T + 6).match)
        self.assertTrue(rt.verify_evidence(r.id, now=T + 7).match)

    def test_pii_scrubbed_before_storage(self):
        eid = self._engagement()
        r = rt.add_evidence(eid, "RESPONSE", operator_id=OP,
                            raw_content="user alice@corp.com card 4111 1111 1111 1111 "
                                        "ssn 123-45-6789", now=T + 5)
        stored = rt.get_evidence(r.id)["raw_content"]
        self.assertIn("REDACTED_EMAIL", stored)
        self.assertIn("REDACTED_CARD", stored)
        self.assertIn("REDACTED_SSN", stored)
        self.assertNotIn("alice@corp.com", stored)

    def test_scrub_pii_helper_leaves_technical_text(self):
        self.assertEqual(rt.scrub_pii("Server: nginx X-Frame-Options: DENY"),
                         "Server: nginx X-Frame-Options: DENY")

    def test_evidence_kind_validated(self):
        eid = self._engagement()
        self.assertEqual(rt.add_evidence(eid, "BOGUS", operator_id=OP, now=T + 5).reason,
                         "INVALID_EVIDENCE_KIND")

    def test_evidence_finding_must_be_in_engagement(self):
        eid = self._engagement()
        other = self._engagement()
        other_fid = self._finding(other)
        r = rt.add_evidence(eid, "RESPONSE", operator_id=OP, finding_id=other_fid, now=T + 6)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "FINDING_NOT_IN_ENGAGEMENT")


# ---------------- Phase 10: defensive gap ----------------

class DefensiveGapTests(RedTeamTestCase):
    def test_no_alert_is_a_gap_and_enqueues_review(self):
        eid = self._engagement()
        r = rt.record_defense_check(eid, "Simulated lateral movement",
                                    "no alert triggered", operator_id=OP, now=T + 5)
        self.assertEqual(r.detail, "DEFENSIVE_GAP_DETECTED")
        self.assertTrue(any(i["summary"].startswith("Defensive gap")
                            for i in rt.list_review_queue(eid)))

    def test_alert_is_detection_confirmed(self):
        eid = self._engagement()
        r = rt.record_defense_check(eid, "Simulated C2 beacon",
                                    "EDR alert triggered and blocked", operator_id=OP, now=T + 5)
        self.assertEqual(r.detail, "DETECTION_CONFIRMED")

    def test_both_signals_required(self):
        eid = self._engagement()
        self.assertEqual(rt.record_defense_check(eid, "x", "  ", operator_id=OP).reason,
                         "BOTH_SIGNALS_REQUIRED")

    def test_both_signals_preserved_verbatim(self):
        eid = self._engagement()
        r = rt.record_defense_check(eid, "RED ACTION TEXT", "TELEMETRY TEXT no alert",
                                    operator_id=OP, now=T + 5)
        rows = rt.list_defense_checks(eid)
        self.assertEqual(rows[0]["red_action"], "RED ACTION TEXT")
        self.assertEqual(rows[0]["telemetry_result"], "TELEMETRY TEXT no alert")


# ---------------- Phase 11/18: timeline + audit + custody ----------------

class TimelineAuditTests(RedTeamTestCase):
    def test_timeline_distinguishes_kinds(self):
        eid = self._engagement()
        rt.register_target(eid, "acme.test", "EXTERNAL_PERIMETER", operator_id=OP, now=T + 10)
        kinds = {e["kind"] for e in rt.get_timeline(eid)}
        self.assertIn("ADMINISTRATIVE_CHANGE", kinds)  # engagement/scope/auth
        self.assertIn("OPERATOR_ACTION", kinds)         # target registration

    def test_evidence_event_carries_hash(self):
        eid = self._engagement()
        r = rt.add_evidence(eid, "RESPONSE", operator_id=OP, raw_content="x", now=T + 5)
        ev_events = [e for e in rt.get_timeline(eid) if e["action"] == "EVIDENCE_COLLECTED"]
        self.assertTrue(ev_events)
        self.assertEqual(ev_events[0]["evidence_hash"], r.detail)

    def test_audit_log_records_key_actions(self):
        eid = self._engagement()
        fid = self._finding(eid)
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, finding_id=fid, raw_content="x",
                        now=T + 6)
        actions = {a["action"] for a in security.get_recent_audit_log(CHAT, limit=50)}
        for a in ("RT_ENGAGEMENT_CREATED", "RT_ENGAGEMENT_AUTHORIZED", "RT_FINDING_CREATED",
                  "RT_EVIDENCE_ADDED"):
            self.assertIn(a, actions)

    def test_custody_trail_is_ordered_and_scoped(self):
        eid = self._engagement()
        fid = self._finding(eid)
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, finding_id=fid, raw_content="x",
                        now=T + 6)
        trail = rt.get_custody_trail(engagement_id=eid, limit=50)
        self.assertTrue(trail)
        stamps = [c["created_at"] for c in trail]
        self.assertEqual(stamps, sorted(stamps))

    def test_custody_requires_a_scope(self):
        self.assertEqual(rt.get_custody_trail(), [])


# ---------------- Phase 15/24: PII + retention ----------------

class GovernanceTests(RedTeamTestCase):
    def tearDown(self):
        rt.RETENTION_TIMELINE_DAYS = 0
        rt.RETENTION_EVIDENCE_DAYS = 0
        super().tearDown()

    def test_zero_retention_keeps_everything(self):
        eid = self._engagement()
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, raw_content="x",
                        now=T - 100 * 86400)
        self.assertEqual(rt.purge_expired(engagement_id=eid, now=T), {})

    def test_configured_retention_purges_old_evidence(self):
        eid = self._engagement()
        rt.RETENTION_EVIDENCE_DAYS = 7
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, raw_content="old",
                        now=T - 30 * 86400)
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, raw_content="recent", now=T - 3600)
        deleted = rt.purge_expired(engagement_id=eid, actor_id=LEAD, now=T)
        self.assertEqual(deleted.get("rt_evidence"), 1)


# ---------------- Phase 20/21: reporting ----------------

class ReportingTests(RedTeamTestCase):
    def _full_engagement(self):
        eid = self._engagement()
        rt.register_target(eid, "acme.test", "EXTERNAL_PERIMETER", operator_id=OP, now=T + 10)
        fid = self._finding(eid, severity="HIGH")
        rt.add_evidence(eid, "RESPONSE", operator_id=OP, finding_id=fid, raw_content="200",
                        now=T + 11)
        rt.reclassify_finding(fid, "VERIFIED_RISK", operator_id=OP, now=T + 12)
        rt.record_defense_check(eid, "sim", "no alert", operator_id=OP, now=T + 13)
        rt.add_ai_analysis(eid, "GENERAL", "AI suggests WAF tuning.", operator_id=OP, now=T + 14)
        return eid

    def test_report_has_all_nine_sections(self):
        eid = self._full_engagement()
        text = rr.format_report(rr.get_report_data(eid))
        for s in (rr.SECTION_EXEC, rr.SECTION_SCOPE, rr.SECTION_VERIFIED, rr.SECTION_LEADS,
                  rr.SECTION_DEFENSE, rr.SECTION_TIMELINE, rr.SECTION_EVIDENCE,
                  rr.SECTION_REMEDIATION, rr.SECTION_AI):
            self.assertIn(s, text)

    def test_ai_is_isolated_from_facts(self):
        eid = self._full_engagement()
        payload = json.loads(rr.export_report_json(eid))
        self.assertIn("ai_analysis_advisory_only", payload)
        self.assertIn("red_team_lead_decisions", payload)
        self.assertIn("system_observations", payload)
        # AI text must not appear in the factual decision layer
        self.assertNotIn("WAF", json.dumps(payload["red_team_lead_decisions"]))

    def test_remediation_package_only_verified(self):
        eid = self._full_engagement()
        # add an unverified exposure that must NOT appear in the package
        rt.create_finding(eid, "unverified thing", operator_id=OP, classification="EXPOSURE",
                          severity="LOW", confidence="LOW", now=T + 20)
        pkg = rr.build_remediation_package(eid)
        self.assertEqual(len(pkg["verified_findings"]), 1)
        self.assertTrue(pkg["verified_findings"][0]["evidence_hashes"])

    def test_report_unknown_engagement_is_none(self):
        self.assertIsNone(rr.get_report_data(99999))
        self.assertIsNone(rr.build_remediation_package(99999))

    def test_csv_export(self):
        eid = self._full_engagement()
        csv_text = rr.export_findings_csv(eid)
        self.assertIn("finding_id,classification", csv_text)
        self.assertIn("VERIFIED_RISK", csv_text)


if __name__ == "__main__":
    unittest.main()
