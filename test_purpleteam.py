"""
test_purpleteam.py — Phase 12 test suite (Purple Team collaboration).

Same isolation pattern as the other suites: a fresh temp SQLite file per
test; the backing red-team engagement built through redteam.py's real API;
every authorization decision made by the real engagement RoE state.

Emphasis on the safety-critical and correctness properties:
  - an exercise cannot RUN (and no detection can be recorded) unless the
    backing engagement is operational; kill-switch / non-authorized /
    expired engagements are denied, fail-closed,
  - the detect → tune → validate loop: a detection gap auto-opens a
    PROPOSED tuning ticket, and a ticket can never reach VALIDATED without
    a human citing a real detecting round (no auto-validate),
  - coverage is derived from the BEST outcome per technique and MTTD from
    round latencies, computed live so they cannot disagree with records,
  - ATT&CK technique ids are validated; PII is scrubbed from stored text;
  - the audit trail and append-only timeline record every action;
  - the report layer renders only what the records contain.
"""

import os
import json
import sqlite3
import tempfile
import unittest

import security
import scope_policy as sp
import redteam as rt
import purpleteam as pt
import purpleteam_report as pr

T = 1_700_000_000
CHAT = -100
LEAD = 900
OP = 901
OUTSIDER = 700


class PurpleTeamTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db = path
        for m in (security, sp, rt, pt):
            m.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()
        rt.redteam_db_init()
        pt.purpleteam_db_init()

    def tearDown(self):
        try:
            os.remove(self._db)
        except OSError:
            pass

    # ---- fixtures ----

    def _engagement(self, authorize=True, include="acme.test", limited=False,
                    expires_at=None):
        e = rt.create_engagement(CHAT, "Acme Pentest", created_by=LEAD)
        eid = e.id
        rt.add_operator(eid, OP, actor_id=LEAD)
        rt.add_scope(eid, "INCLUDE", "DOMAIN", include, actor_id=LEAD)
        if authorize:
            rt.authorize_engagement(eid, approver_id=LEAD, roe_reference="SOW-1",
                                    limited=limited, expires_at=expires_at, now=T)
        return eid

    def _running_exercise(self, **kw):
        eid = self._engagement(**kw)
        x = pt.create_exercise(CHAT, eid, "Q3 Purple", created_by=LEAD, now=T)
        pt.start_exercise(x.id, actor_id=LEAD, now=T + 1)
        return eid, x.id

    def _emu(self, xid, technique="T1059.001", tactic="Execution", name="PowerShell"):
        return pt.add_emulation(xid, technique, planned_by=OP, tactic=tactic,
                                technique_name=name, now=T + 2).id


# ---------------- DB init ----------------

class DatabaseInitTests(PurpleTeamTestCase):
    def test_all_tables_created(self):
        conn = sqlite3.connect(self._db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        for t in ("pt_exercises", "pt_emulations", "pt_detections",
                  "pt_tuning", "pt_timeline"):
            self.assertIn(t, tables)

    def test_init_is_idempotent(self):
        pt.purpleteam_db_init()
        pt.purpleteam_db_init()  # must not raise


# ---------------- Exercise lifecycle & authorization ----------------

class ExerciseLifecycleTests(PurpleTeamTestCase):
    def test_create_requires_existing_engagement_in_chat(self):
        r = pt.create_exercise(CHAT, 999, "x", created_by=LEAD)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "ENGAGEMENT_NOT_FOUND")

    def test_create_rejects_engagement_from_other_chat(self):
        eid = self._engagement()
        r = pt.create_exercise(-200, eid, "x", created_by=LEAD)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "ENGAGEMENT_WRONG_CHAT")

    def test_exercise_starts_planned(self):
        eid = self._engagement()
        x = pt.create_exercise(CHAT, eid, "Q3 Purple", created_by=LEAD)
        self.assertTrue(x.ok)
        self.assertEqual(pt.get_exercise(x.id)["status"], "PLANNED")

    def test_cannot_start_without_operational_engagement(self):
        eid = self._engagement(authorize=False)  # still PENDING_APPROVAL
        x = pt.create_exercise(CHAT, eid, "Q3 Purple", created_by=LEAD)
        r = pt.start_exercise(x.id, actor_id=LEAD)
        self.assertFalse(r.ok)
        self.assertTrue(r.reason.startswith("ENGAGEMENT_"))
        self.assertEqual(pt.get_exercise(x.id)["status"], "PLANNED")

    def test_kill_switch_blocks_start(self):
        eid = self._engagement()
        rt.trigger_kill_switch(eid, actor_id=LEAD, reason="stop")
        x = pt.create_exercise(CHAT, eid, "Q3 Purple", created_by=LEAD)
        r = pt.start_exercise(x.id, actor_id=LEAD)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "ENGAGEMENT_TERMINATED")

    def test_expired_engagement_blocks_start(self):
        eid = self._engagement(expires_at=T + 10)
        x = pt.create_exercise(CHAT, eid, "Q3 Purple", created_by=LEAD)
        r = pt.start_exercise(x.id, actor_id=LEAD, now=T + 100)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "ENGAGEMENT_EXPIRED")

    def test_limited_scope_engagement_is_operational(self):
        eid = self._engagement(limited=True)
        self.assertEqual(rt.get_engagement(eid)["status"], "LIMITED_SCOPE")
        x = pt.create_exercise(CHAT, eid, "Q3 Purple", created_by=LEAD)
        r = pt.start_exercise(x.id, actor_id=LEAD, now=T + 1)
        self.assertTrue(r.ok)

    def test_double_start_rejected(self):
        eid, xid = self._running_exercise()
        r = pt.start_exercise(xid, actor_id=LEAD)
        self.assertFalse(r.ok)

    def test_complete_and_cancel_are_terminal(self):
        eid, xid = self._running_exercise()
        self.assertTrue(pt.complete_exercise(xid, actor_id=LEAD).ok)
        self.assertFalse(pt.cancel_exercise(xid, actor_id=LEAD).ok)
        self.assertEqual(pt.get_exercise(xid)["status"], "COMPLETED")


# ---------------- ATT&CK emulation planning ----------------

class EmulationTests(PurpleTeamTestCase):
    def test_valid_technique_ids_accepted(self):
        eid = self._engagement()
        x = pt.create_exercise(CHAT, eid, "x", created_by=LEAD)
        for tid in ("T1059", "T1059.001", "t1003"):
            r = pt.add_emulation(x.id, tid, planned_by=OP)
            self.assertTrue(r.ok, tid)
            self.assertEqual(r.detail, tid.upper())

    def test_invalid_technique_ids_rejected(self):
        eid = self._engagement()
        x = pt.create_exercise(CHAT, eid, "x", created_by=LEAD)
        for tid in ("T105", "1059", "T10590", "T1059.1", "'; DROP TABLE"):
            r = pt.add_emulation(x.id, tid, planned_by=OP)
            self.assertFalse(r.ok, tid)
            self.assertEqual(r.reason, "INVALID_TECHNIQUE_ID")

    def test_emulation_can_be_planned_before_start(self):
        eid = self._engagement()
        x = pt.create_exercise(CHAT, eid, "x", created_by=LEAD)
        self.assertTrue(pt.add_emulation(x.id, "T1059", planned_by=OP).ok)

    def test_emulation_rejected_on_terminal_exercise(self):
        eid, xid = self._running_exercise()
        pt.complete_exercise(xid, actor_id=LEAD)
        r = pt.add_emulation(xid, "T1059", planned_by=OP)
        self.assertFalse(r.ok)


# ---------------- Detect step ----------------

class DetectionTests(PurpleTeamTestCase):
    def test_detection_requires_running_exercise(self):
        eid = self._engagement()
        x = pt.create_exercise(CHAT, eid, "x", created_by=LEAD)
        emu = pt.add_emulation(x.id, "T1059", planned_by=OP).id
        r = pt.record_detection(x.id, emu, "DETECTED", recorded_by=OP)
        self.assertFalse(r.ok)
        self.assertTrue(r.reason.startswith("EXERCISE_NOT_RUNNING"))

    def test_invalid_outcome_rejected(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        r = pt.record_detection(xid, emu, "MAYBE", recorded_by=OP)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "INVALID_OUTCOME")

    def test_emulation_must_belong_to_exercise(self):
        eid, xid = self._running_exercise()
        # emulation from a different exercise
        eid2 = self._engagement()
        x2 = pt.create_exercise(CHAT, eid2, "other", created_by=LEAD)
        foreign = pt.add_emulation(x2.id, "T1003", planned_by=OP).id
        r = pt.record_detection(xid, foreign, "DETECTED", recorded_by=OP)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "EMULATION_NOT_FOUND")

    def test_mttd_computed_from_latency(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        r = pt.record_detection(xid, emu, "DETECTED", recorded_by=OP,
                                executed_at=1000, detected_at=1042)
        self.assertTrue(r.ok)
        det = pt.list_detections(xid, emulation_id=emu)[0]
        self.assertEqual(det["detect_latency"], 42)

    def test_negative_latency_stored_as_none(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        pt.record_detection(xid, emu, "DETECTED", recorded_by=OP,
                            executed_at=2000, detected_at=1000)
        det = pt.list_detections(xid, emulation_id=emu)[0]
        self.assertIsNone(det["detect_latency"])

    def test_missed_ignores_detected_at(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        pt.record_detection(xid, emu, "MISSED", recorded_by=OP,
                            executed_at=1000, detected_at=1010)
        det = pt.list_detections(xid, emulation_id=emu)[0]
        self.assertIsNone(det["detected_at"])
        self.assertIsNone(det["detect_latency"])

    def test_recording_marks_emulation_executed(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        pt.record_detection(xid, emu, "DETECTED", recorded_by=OP)
        self.assertEqual(pt.get_emulation(emu)["status"], "EXECUTED")

    def test_pii_scrubbed_from_telemetry(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        pt.record_detection(xid, emu, "DETECTED", recorded_by=OP,
                            telemetry="user victim@example.com triggered rule")
        det = pt.list_detections(xid, emulation_id=emu)[0]
        self.assertNotIn("victim@example.com", det["telemetry"])
        self.assertIn("[REDACTED_EMAIL]", det["telemetry"])


# ---------------- Tune step (gap -> ticket) ----------------

class TuningLifecycleTests(PurpleTeamTestCase):
    def test_gap_outcome_auto_opens_tuning(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        r = pt.record_detection(xid, emu, "MISSED", recorded_by=OP)
        self.assertEqual(r.detail, "GAP")
        tickets = pt.list_tuning(xid)
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0]["status"], "PROPOSED")
        self.assertTrue(tickets[0]["origin"].startswith("AUTO:"))

    def test_logged_only_is_a_gap(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        r = pt.record_detection(xid, emu, "LOGGED_ONLY", recorded_by=OP)
        self.assertEqual(r.detail, "GAP")
        self.assertEqual(len(pt.list_tuning(xid)), 1)

    def test_win_outcomes_open_no_ticket(self):
        eid, xid = self._running_exercise()
        for out in ("DETECTED", "PREVENTED", "ALERTED"):
            emu = self._emu(xid, technique="T1059")
            pt.record_detection(xid, emu, out, recorded_by=OP)
        self.assertEqual(pt.list_tuning(xid), [])

    def test_transition_table_enforced(self):
        eid, xid = self._running_exercise()
        tid = pt.propose_tuning(xid, "manual rule", proposed_by=OP).id
        # PROPOSED -> VALIDATED is not allowed via set_tuning_status
        r = pt.set_tuning_status(tid, "VALIDATED", actor_id=LEAD)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "USE_VALIDATE_TUNING")
        # PROPOSED -> IMPLEMENTED ok; IMPLEMENTED -> IN_PROGRESS ok
        self.assertTrue(pt.set_tuning_status(tid, "IMPLEMENTED", actor_id=LEAD).ok)
        self.assertTrue(pt.set_tuning_status(tid, "IN_PROGRESS", actor_id=LEAD).ok)

    def test_illegal_transition_rejected(self):
        eid, xid = self._running_exercise()
        tid = pt.propose_tuning(xid, "rule", proposed_by=OP).id
        pt.set_tuning_status(tid, "REJECTED", actor_id=LEAD)
        r = pt.set_tuning_status(tid, "IMPLEMENTED", actor_id=LEAD)
        self.assertFalse(r.ok)
        self.assertTrue(r.reason.startswith("ILLEGAL_TRANSITION"))

    def test_propose_validates_technique(self):
        eid, xid = self._running_exercise()
        r = pt.propose_tuning(xid, "rule", proposed_by=OP, technique_id="nope")
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "INVALID_TECHNIQUE_ID")


# ---------------- Validate step (no auto-validate) ----------------

class ValidationTests(PurpleTeamTestCase):
    def _implemented_ticket(self, xid, technique="T1059.001"):
        emu = self._emu(xid, technique=technique)
        pt.record_detection(xid, emu, "MISSED", recorded_by=OP)  # opens ticket
        tid = pt.list_tuning(xid)[0]["tuning_id"]
        pt.set_tuning_status(tid, "IMPLEMENTED", actor_id=LEAD)
        return emu, tid

    def test_cannot_validate_before_implemented(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        pt.record_detection(xid, emu, "MISSED", recorded_by=OP)
        tid = pt.list_tuning(xid)[0]["tuning_id"]  # still PROPOSED
        good = pt.record_detection(xid, emu, "DETECTED", recorded_by=OP).id
        r = pt.validate_tuning(tid, good, actor_id=LEAD)
        self.assertFalse(r.ok)
        self.assertTrue(r.reason.startswith("NOT_IMPLEMENTED"))

    def test_cannot_validate_with_a_gap_round(self):
        eid, xid = self._running_exercise()
        emu, tid = self._implemented_ticket(xid)
        still_gap = pt.record_detection(xid, emu, "MISSED", recorded_by=OP).id
        r = pt.validate_tuning(tid, still_gap, actor_id=LEAD)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "DETECTION_STILL_A_GAP")

    def test_validate_requires_matching_technique(self):
        eid, xid = self._running_exercise()
        emu, tid = self._implemented_ticket(xid, technique="T1059.001")
        other = self._emu(xid, technique="T1003")
        wrong = pt.record_detection(xid, other, "DETECTED", recorded_by=OP).id
        r = pt.validate_tuning(tid, wrong, actor_id=LEAD)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "TECHNIQUE_MISMATCH")

    def test_successful_validation(self):
        eid, xid = self._running_exercise()
        emu, tid = self._implemented_ticket(xid, technique="T1059.001")
        good = pt.record_detection(xid, emu, "DETECTED", recorded_by=OP,
                                   executed_at=T + 50, detected_at=T + 60).id
        r = pt.validate_tuning(tid, good, actor_id=LEAD, note="rule now fires")
        self.assertTrue(r.ok)
        ticket = pt.get_tuning(tid)
        self.assertEqual(ticket["status"], "VALIDATED")
        self.assertEqual(ticket["validated_detection_id"], good)
        self.assertEqual(ticket["validated_by"], LEAD)

    def test_validated_is_terminal(self):
        eid, xid = self._running_exercise()
        emu, tid = self._implemented_ticket(xid)
        good = pt.record_detection(xid, emu, "DETECTED", recorded_by=OP).id
        pt.validate_tuning(tid, good, actor_id=LEAD)
        r = pt.set_tuning_status(tid, "REJECTED", actor_id=LEAD)
        self.assertFalse(r.ok)


# ---------------- Coverage & metrics (derived) ----------------

class CoverageMetricsTests(PurpleTeamTestCase):
    def test_best_outcome_wins_across_rounds(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid, technique="T1059.001")
        pt.record_detection(xid, emu, "MISSED", recorded_by=OP)
        pt.record_detection(xid, emu, "ALERTED", recorded_by=OP)
        pt.record_detection(xid, emu, "DETECTED", recorded_by=OP)
        cov = {c["technique_id"]: c for c in pt.get_technique_coverage(xid)}
        self.assertEqual(cov["T1059.001"]["best_outcome"], "DETECTED")
        self.assertEqual(cov["T1059.001"]["coverage"], "DETECTION")
        self.assertEqual(cov["T1059.001"]["rounds"], 3)

    def test_coverage_states_map_from_outcome(self):
        eid, xid = self._running_exercise()
        mapping = {"T1001": ("MISSED", "NONE"),
                   "T1002": ("LOGGED_ONLY", "TELEMETRY"),
                   "T1003": ("ALERTED", "PARTIAL"),
                   "T1004": ("DETECTED", "DETECTION"),
                   "T1005": ("PREVENTED", "DETECTION")}
        for tid, (out, _) in mapping.items():
            emu = self._emu(xid, technique=tid)
            pt.record_detection(xid, emu, out, recorded_by=OP)
        cov = {c["technique_id"]: c["coverage"] for c in pt.get_technique_coverage(xid)}
        for tid, (_, expected) in mapping.items():
            self.assertEqual(cov[tid], expected, tid)

    def test_planned_but_unexecuted_technique_is_none(self):
        eid, xid = self._running_exercise()
        self._emu(xid, technique="T1059.001")  # planned, never executed
        cov = {c["technique_id"]: c for c in pt.get_technique_coverage(xid)}
        self.assertEqual(cov["T1059.001"]["coverage"], "NONE")
        self.assertEqual(cov["T1059.001"]["rounds"], 0)

    def test_metrics_rollup(self):
        eid, xid = self._running_exercise()
        e1 = self._emu(xid, technique="T1059.001")
        e2 = self._emu(xid, technique="T1003")
        pt.record_detection(xid, e1, "DETECTED", recorded_by=OP,
                            executed_at=100, detected_at=140)
        pt.record_detection(xid, e2, "MISSED", recorded_by=OP)
        m = pt.get_exercise_metrics(xid)
        self.assertEqual(m["detection_rounds"], 2)
        self.assertEqual(m["gaps"], 1)
        self.assertAlmostEqual(m["detection_rate"], 0.5)
        self.assertEqual(m["mttd_mean"], 40.0)
        self.assertEqual(m["mttd_samples"], 1)
        self.assertEqual(m["techniques"], 2)
        self.assertEqual(m["techniques_with_detection"], 1)
        self.assertEqual(m["coverage_histogram"]["DETECTION"], 1)
        self.assertEqual(m["coverage_histogram"]["NONE"], 1)


# ---------------- Audit & timeline ----------------

class AuditTimelineTests(PurpleTeamTestCase):
    def test_timeline_records_lifecycle(self):
        eid, xid = self._running_exercise()
        emu = self._emu(xid)
        pt.record_detection(xid, emu, "MISSED", recorded_by=OP)
        kinds = {ev["action"] for ev in pt.get_timeline(xid, limit=100)}
        self.assertIn("EXERCISE_CREATED", kinds)
        self.assertIn("EXERCISE_STARTED", kinds)
        self.assertIn("EMULATION_ADDED", kinds)
        self.assertIn("DETECTION_RECORDED", kinds)
        self.assertIn("DETECTION_GAP", kinds)

    def test_audit_log_written(self):
        eid, xid = self._running_exercise()
        conn = sqlite3.connect(self._db)
        conn.row_factory = sqlite3.Row
        actions = {r["action"] for r in conn.execute(
            "SELECT action FROM audit_log WHERE action LIKE 'PT_%'").fetchall()}
        conn.close()
        self.assertIn("PT_EXERCISE_CREATED", actions)
        self.assertIn("PT_EXERCISE_STARTED", actions)


# ---------------- Report layer ----------------

class ReportTests(PurpleTeamTestCase):
    def _populated(self):
        eid, xid = self._running_exercise()
        e1 = self._emu(xid, technique="T1059.001", tactic="Execution")
        e2 = self._emu(xid, technique="T1003", tactic="Credential Access")
        pt.record_detection(xid, e1, "DETECTED", recorded_by=OP,
                            executed_at=100, detected_at=142)
        pt.record_detection(xid, e2, "MISSED", recorded_by=OP)
        return xid

    def test_report_data_none_for_missing(self):
        self.assertIsNone(pr.get_report_data(9999))

    def test_format_report_mentions_key_facts(self):
        xid = self._populated()
        text = pr.format_report(pr.get_report_data(xid))
        self.assertIn("PURPLE TEAM EXERCISE REPORT", text)
        self.assertIn("T1059.001", text)
        self.assertIn("T1003", text)
        self.assertIn("MITRE ATT&CK", text)

    def test_json_export_roundtrips(self):
        xid = self._populated()
        payload = pr.export_report_json(xid)
        data = json.loads(payload)
        self.assertEqual(data["exercise"]["exercise_id"], xid)
        self.assertIn("metrics", data)

    def test_coverage_csv_has_row_per_technique(self):
        xid = self._populated()
        csv_text = pr.export_coverage_csv(xid)
        lines = [l for l in csv_text.splitlines() if l.strip()]
        self.assertEqual(len(lines), 3)  # header + 2 techniques
        self.assertIn("technique_id", lines[0])

    def test_navigator_layer_valid_json(self):
        xid = self._populated()
        layer = json.loads(pr.export_attack_navigator_layer(xid))
        self.assertEqual(layer["domain"], "enterprise-attack")
        ids = {t["techniqueID"] for t in layer["techniques"]}
        self.assertEqual(ids, {"T1059.001", "T1003"})


if __name__ == "__main__":
    unittest.main()
