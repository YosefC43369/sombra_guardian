"""
test_bb_case.py — Phase 7 test suite.

Same isolation pattern as test_findings.py / test_scope_policy.py: each
test gets a fresh temp SQLite file, so tests never share state and can
run in any order. Everything is exercised through bb_case.py's real
public API, with Programs/Authorizations/Scope/Findings built through
scope_policy.py's and findings.py's real APIs rather than by poking at
tables directly -- that is the actual surface app.py calls.
"""

import os
import sqlite3
import tempfile
import unittest

import security
import scope_policy as sp
import findings as f
import bb_case as bc


class BBCaseTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        sp.DB_PATH = path
        f.DB_PATH = path
        bc.DB_PATH = path
        security.security_db_init()
        sp.scope_policy_db_init()
        f.findings_db_init()
        bc.bb_case_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers ----

    def _fully_authorized_program(self, include="example.com", chat_id=1):
        pid = sp.create_program(chat_id, "Acme Bug Bounty", created_by=999)
        sp.set_program_status(pid, sp.ProgramStatus.ACTIVE.value, 999)
        aid = sp.import_authorization(
            pid, source_type="email", actor_user_id=999,
            source_reference="security@acme.test", authorization_reference="ACME-2026-01",
        )
        sp.review_authorization(aid, approve=True, reviewer_user_id=1000)
        sp.add_scope_rule(pid, sp.RuleType.INCLUDE.value, sp.TargetType.DOMAIN.value,
                          include, actor_user_id=999)
        return pid

    def _finding(self, program_id=None, target="example.com", severity="HIGH"):
        pid = program_id if program_id is not None else self._fully_authorized_program()
        result = f.create_finding(pid, target, "XSS in search box", created_by=555,
                                  severity=severity)
        self.assertTrue(result.ok, msg=f"fixture finding failed: {result.reason}")
        return result.finding_id

    def _case(self, **kwargs):
        finding_id = kwargs.pop("finding_id", None) or self._finding()
        result = bc.create_case(finding_id, created_by=555, **kwargs)
        self.assertTrue(result.ok, msg=f"fixture case failed: {result.reason}")
        return result.case_id

    def _assigned_case(self, assignee=777):
        case_id = self._case()
        self.assertTrue(bc.update_case_status(case_id, "TRIAGE", 999).ok)
        self.assertTrue(bc.assign_case(case_id, assignee, actor_user_id=999).ok)
        self.assertTrue(bc.update_case_status(case_id, "ASSIGNED", 999).ok)
        return case_id

    def _raw(self, sql, params=()):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ================= Case creation =================

    def test_create_case_for_valid_finding(self):
        finding_id = self._finding()
        result = bc.create_case(finding_id, created_by=555)
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.case_id)

    def test_new_case_starts_open_normal_and_unassigned(self):
        case = bc.get_case(self._case())
        self.assertEqual(case["status"], "OPEN")
        self.assertEqual(case["priority"], "NORMAL")
        self.assertIsNone(case["assignee"])
        self.assertIsNone(case["closed_at"])

    def test_create_case_for_nonexistent_finding_rejected(self):
        result = bc.create_case(999999, created_by=555)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FINDING_NOT_FOUND")

    def test_create_case_rejects_invalid_finding_id(self):
        for bad in (0, -1, "1", None, True, 1.5):
            with self.subTest(finding_id=bad):
                result = bc.create_case(bad, created_by=555)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "INVALID_FINDING_ID")

    def test_create_case_rejects_invalid_creator(self):
        result = bc.create_case(self._finding(), created_by=0)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_ACTOR")

    def test_create_case_rejects_invalid_priority(self):
        result = bc.create_case(self._finding(), created_by=555, priority="SUPER_URGENT")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_PRIORITY")

    def test_create_case_accepts_explicit_priority(self):
        case_id = self._case(priority="URGENT")
        self.assertEqual(bc.get_case(case_id)["priority"], "URGENT")

    def test_duplicate_active_case_for_same_finding_rejected(self):
        finding_id = self._finding()
        first = bc.create_case(finding_id, created_by=555)
        second = bc.create_case(finding_id, created_by=556)
        self.assertTrue(first.ok)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ACTIVE_CASE_EXISTS")
        self.assertEqual(second.case_id, first.case_id)

    def test_new_case_allowed_after_previous_one_is_cancelled(self):
        finding_id = self._finding()
        first = bc.create_case(finding_id, created_by=555)
        self.assertTrue(bc.update_case_status(first.case_id, "CANCELLED", 999).ok)
        second = bc.create_case(finding_id, created_by=555)
        self.assertTrue(second.ok)
        self.assertNotEqual(second.case_id, first.case_id)

    def test_database_level_unique_index_blocks_second_active_case(self):
        """The Python-side check is not the only guard: a direct INSERT
        that bypasses create_case() must still be refused by SQLite."""
        finding_id = self._finding()
        bc.create_case(finding_id, created_by=555)
        conn = sqlite3.connect(self._db_path)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO bb_cases (finding_id, status, priority, created_by, "
                "created_at, updated_at) VALUES (?, 'OPEN', 'NORMAL', 1, 1, 1)",
                (finding_id,),
            )
            conn.commit()
        conn.close()

    def test_case_row_persists_in_database(self):
        case_id = self._case()
        rows = self._raw("SELECT * FROM bb_cases WHERE case_id=?", (case_id,))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "OPEN")

    def test_case_does_not_duplicate_finding_fields(self):
        """The Finding stays the source of truth: no title/target/
        severity column is copied onto bb_cases."""
        columns = {r["name"] for r in self._raw("PRAGMA table_info(bb_cases)")}
        for leaked in ("title", "target", "severity", "description", "program_id"):
            self.assertNotIn(leaked, columns)

    def test_get_case_by_finding_returns_active_case_only(self):
        finding_id = self._finding()
        case_id = bc.create_case(finding_id, created_by=555).case_id
        self.assertEqual(bc.get_case_by_finding(finding_id)["case_id"], case_id)
        bc.update_case_status(case_id, "CANCELLED", 999)
        self.assertIsNone(bc.get_case_by_finding(finding_id))

    # ================= Assignment =================

    def test_assign_case(self):
        case_id = self._case()
        result = bc.assign_case(case_id, 777, actor_user_id=999)
        self.assertTrue(result.ok)
        self.assertEqual(bc.get_case(case_id)["assignee"], 777)

    def test_reassign_case_to_a_different_handler(self):
        case_id = self._case()
        bc.assign_case(case_id, 777, actor_user_id=999)
        self.assertTrue(bc.assign_case(case_id, 888, actor_user_id=999).ok)
        self.assertEqual(bc.get_case(case_id)["assignee"], 888)

    def test_assign_to_same_handler_twice_is_rejected(self):
        case_id = self._case()
        bc.assign_case(case_id, 777, actor_user_id=999)
        result = bc.assign_case(case_id, 777, actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ALREADY_ASSIGNED")

    def test_unassign_case(self):
        case_id = self._case()
        bc.assign_case(case_id, 777, actor_user_id=999)
        self.assertTrue(bc.unassign_case(case_id, actor_user_id=999).ok)
        self.assertIsNone(bc.get_case(case_id)["assignee"])

    def test_unassign_when_not_assigned_is_rejected(self):
        result = bc.unassign_case(self._case(), actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NOT_ASSIGNED")

    def test_assign_nonexistent_case_rejected(self):
        result = bc.assign_case(999999, 777, actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CASE_NOT_FOUND")

    def test_assign_rejects_invalid_assignee(self):
        case_id = self._case()
        for bad in (0, -5, "777", None, True):
            with self.subTest(assignee=bad):
                result = bc.assign_case(case_id, bad, actor_user_id=999)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "INVALID_ASSIGNEE")

    def test_assign_rejects_terminal_case(self):
        case_id = self._case()
        bc.update_case_status(case_id, "CANCELLED", 999)
        result = bc.assign_case(case_id, 777, actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CASE_TERMINAL")

    def test_unassigning_an_assigned_case_demotes_status_to_triage(self):
        """ASSIGNED must never be observable without an assignee."""
        case_id = self._assigned_case()
        self.assertEqual(bc.get_case(case_id)["status"], "ASSIGNED")
        self.assertTrue(bc.unassign_case(case_id, actor_user_id=999).ok)
        case = bc.get_case(case_id)
        self.assertIsNone(case["assignee"])
        self.assertEqual(case["status"], "TRIAGE")

    def test_unassign_demotion_is_recorded_on_the_timeline(self):
        case_id = self._assigned_case()
        bc.unassign_case(case_id, actor_user_id=999)
        events = [e["event_type"] for e in bc.list_timeline(case_id)]
        self.assertEqual(events[-2:], ["UNASSIGNED", "STATUS_CHANGED"])

    # ================= Priority =================

    def test_every_valid_priority_is_accepted(self):
        for priority in sorted(bc.VALID_PRIORITIES):
            with self.subTest(priority=priority):
                case_id = self._case()
                result = bc.set_case_priority(case_id, priority, actor_user_id=999)
                if priority == "NORMAL":  # already the default
                    self.assertFalse(result.ok)
                    self.assertEqual(result.reason, "PRIORITY_UNCHANGED")
                else:
                    self.assertTrue(result.ok)
                    self.assertEqual(bc.get_case(case_id)["priority"], priority)

    def test_invalid_priority_rejected(self):
        case_id = self._case()
        for bad in ("CRITICAL", "urgent", "", None, 3, "HIGH; DROP TABLE bb_cases"):
            with self.subTest(priority=bad):
                result = bc.set_case_priority(case_id, bad, actor_user_id=999)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "INVALID_PRIORITY")

    def test_priority_is_independent_from_finding_severity(self):
        finding_id = self._finding(severity="CRITICAL")
        case_id = bc.create_case(finding_id, created_by=555).case_id
        bc.set_case_priority(case_id, "LOW", actor_user_id=999)
        self.assertEqual(bc.get_case(case_id)["priority"], "LOW")
        self.assertEqual(f.get_finding(finding_id)["severity"], "CRITICAL")

    def test_priority_change_never_writes_to_the_finding(self):
        finding_id = self._finding(severity="LOW")
        before = f.get_finding(finding_id)
        case_id = bc.create_case(finding_id, created_by=555).case_id
        bc.set_case_priority(case_id, "URGENT", actor_user_id=999)
        self.assertEqual(f.get_finding(finding_id), before)

    def test_priority_change_on_terminal_case_rejected(self):
        case_id = self._case()
        bc.update_case_status(case_id, "CANCELLED", 999)
        result = bc.set_case_priority(case_id, "HIGH", actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CASE_TERMINAL")

    # ================= Status workflow =================

    def test_valid_transition_open_to_triage(self):
        case_id = self._case()
        self.assertTrue(bc.update_case_status(case_id, "TRIAGE", 999).ok)
        self.assertEqual(bc.get_case(case_id)["status"], "TRIAGE")

    def test_full_happy_path_to_closed(self):
        case_id = self._case()
        bc.update_case_status(case_id, "TRIAGE", 999)
        bc.assign_case(case_id, 777, actor_user_id=999)
        for status in ("ASSIGNED", "IN_PROGRESS", "RESOLVED", "CLOSED"):
            with self.subTest(status=status):
                self.assertTrue(bc.update_case_status(case_id, status, 999).ok)
        self.assertEqual(bc.get_case(case_id)["status"], "CLOSED")

    def test_invalid_transition_rejected(self):
        case_id = self._case()
        for bad_target in ("RESOLVED", "CLOSED", "IN_PROGRESS", "ASSIGNED"):
            with self.subTest(target=bad_target):
                result = bc.update_case_status(case_id, bad_target, 999)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "INVALID_TRANSITION")

    def test_unknown_status_string_rejected(self):
        case_id = self._case()
        for bad in ("DONE", "open", "", None, 7, "TRIAGE'); DROP TABLE bb_cases;--"):
            with self.subTest(status=bad):
                result = bc.update_case_status(case_id, bad, 999)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "INVALID_STATUS")

    def test_terminal_closed_case_cannot_be_reopened(self):
        case_id = self._case()
        bc.update_case_status(case_id, "TRIAGE", 999)
        bc.assign_case(case_id, 777, actor_user_id=999)
        bc.update_case_status(case_id, "ASSIGNED", 999)
        bc.update_case_status(case_id, "IN_PROGRESS", 999)
        bc.update_case_status(case_id, "RESOLVED", 999)
        bc.update_case_status(case_id, "CLOSED", 999)
        for target in sorted(bc.VALID_CASE_STATUSES):
            with self.subTest(target=target):
                result = bc.update_case_status(case_id, target, 999)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "INVALID_TRANSITION")

    def test_terminal_cancelled_case_cannot_be_reopened(self):
        case_id = self._case()
        bc.update_case_status(case_id, "CANCELLED", 999)
        for target in sorted(bc.VALID_CASE_STATUSES):
            with self.subTest(target=target):
                self.assertFalse(bc.update_case_status(case_id, target, 999).ok)

    def test_every_terminal_state_has_no_outgoing_transition(self):
        for terminal in bc.TERMINAL_CASE_STATUSES:
            with self.subTest(terminal=terminal):
                self.assertEqual(bc._ALLOWED_CASE_TRANSITIONS[terminal], set())

    def test_assigned_status_requires_an_assignee(self):
        case_id = self._case()
        bc.update_case_status(case_id, "TRIAGE", 999)
        result = bc.update_case_status(case_id, "ASSIGNED", 999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ASSIGNEE_REQUIRED")

    def test_closed_at_is_stamped_only_on_terminal_states(self):
        case_id = self._case()
        bc.update_case_status(case_id, "TRIAGE", 999)
        self.assertIsNone(bc.get_case(case_id)["closed_at"])
        bc.update_case_status(case_id, "CANCELLED", 999)
        self.assertIsNotNone(bc.get_case(case_id)["closed_at"])

    def test_status_change_never_writes_to_the_finding(self):
        finding_id = self._finding()
        before = f.get_finding(finding_id)
        case_id = bc.create_case(finding_id, created_by=555).case_id
        bc.update_case_status(case_id, "TRIAGE", 999)
        bc.update_case_status(case_id, "CANCELLED", 999)
        self.assertEqual(f.get_finding(finding_id), before)

    def test_case_status_does_not_contradict_finding_state_machine(self):
        """The two machines are independent: no Case status name is
        silently reused as a Finding status, and moving one never moves
        the other."""
        finding_id = self._finding()
        case_id = bc.create_case(finding_id, created_by=555).case_id
        bc.update_case_status(case_id, "TRIAGE", 999)
        self.assertEqual(f.get_finding(finding_id)["status"], "OPEN")
        f.update_finding_status(finding_id, "TRIAGED", actor_user_id=999)
        self.assertEqual(bc.get_case(case_id)["status"], "TRIAGE")
        self.assertEqual(f.get_finding(finding_id)["status"], "TRIAGED")

    def test_status_update_on_nonexistent_case_rejected(self):
        result = bc.update_case_status(999999, "TRIAGE", 999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CASE_NOT_FOUND")

    def test_status_update_rejects_invalid_actor(self):
        result = bc.update_case_status(self._case(), "TRIAGE", 0)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_ACTOR")

    # ================= Timeline =================

    def test_case_creation_writes_a_timeline_event(self):
        entries = bc.list_timeline(self._case())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["event_type"], "CASE_CREATED")

    def test_add_note(self):
        case_id = self._case()
        self.assertTrue(bc.add_case_note(case_id, 555, "รอทีม infra ยืนยัน").ok)
        entries = bc.list_timeline(case_id)
        self.assertEqual(entries[-1]["event_type"], "NOTE_ADDED")
        self.assertEqual(entries[-1]["message"], "รอทีม infra ยืนยัน")

    def test_note_rejects_empty_and_oversized_text(self):
        case_id = self._case()
        for bad in ("", "   ", None, "x" * (bc.MAX_NOTE_LEN + 1), "has\x00nul", 123):
            with self.subTest(note=repr(bad)[:30]):
                result = bc.add_case_note(case_id, 555, bad)
                self.assertFalse(result.ok)
                self.assertEqual(result.reason, "INVALID_NOTE")

    def test_note_on_terminal_case_rejected(self):
        case_id = self._case()
        bc.update_case_status(case_id, "CANCELLED", 999)
        result = bc.add_case_note(case_id, 555, "late note")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CASE_TERMINAL")

    def test_lifecycle_events_are_recorded_automatically(self):
        case_id = self._case()
        bc.set_case_priority(case_id, "HIGH", actor_user_id=999)
        bc.update_case_status(case_id, "TRIAGE", 999)
        bc.assign_case(case_id, 777, actor_user_id=999)
        bc.add_case_note(case_id, 555, "note")
        events = [e["event_type"] for e in bc.list_timeline(case_id)]
        self.assertEqual(
            events,
            ["CASE_CREATED", "PRIORITY_CHANGED", "STATUS_CHANGED", "ASSIGNED", "NOTE_ADDED"],
        )

    def test_timeline_is_ordered_oldest_first(self):
        case_id = self._case()
        for i in range(5):
            bc.add_case_note(case_id, 555, f"note {i}")
        entries = bc.list_timeline(case_id)
        ids = [e["timeline_id"] for e in entries]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(entries[-1]["message"], "note 4")

    def test_timeline_records_the_actor(self):
        case_id = self._case()
        bc.add_case_note(case_id, 4242, "who did this")
        self.assertEqual(bc.list_timeline(case_id)[-1]["actor"], 4242)

    def test_timeline_limit_and_offset(self):
        case_id = self._case()
        for i in range(10):
            bc.add_case_note(case_id, 555, f"note {i}")
        page = bc.list_timeline(case_id, limit=3, offset=1)
        self.assertEqual(len(page), 3)
        self.assertEqual(page[0]["message"], "note 0")

    def test_timeline_for_invalid_case_id_is_empty(self):
        for bad in (0, -1, "1", None, True):
            with self.subTest(case_id=bad):
                self.assertEqual(bc.list_timeline(bad), [])

    def test_opening_note_is_stored_on_the_creation_event(self):
        finding_id = self._finding()
        case_id = bc.create_case(finding_id, created_by=555, note="เปิดเคสตามรายงานลูกค้า").case_id
        self.assertEqual(bc.list_timeline(case_id)[0]["message"], "เปิดเคสตามรายงานลูกค้า")

    # ================= Listing =================

    def test_list_cases_filters_by_status(self):
        open_case = self._case()
        other = self._case()
        bc.update_case_status(other, "TRIAGE", 999)
        ids = [c["case_id"] for c in bc.list_cases(status="TRIAGE")]
        self.assertIn(other, ids)
        self.assertNotIn(open_case, ids)

    def test_list_cases_filters_by_priority(self):
        case_id = self._case()
        bc.set_case_priority(case_id, "URGENT", actor_user_id=999)
        self._case()
        ids = [c["case_id"] for c in bc.list_cases(priority="URGENT")]
        self.assertEqual(ids, [case_id])

    def test_list_cases_filters_by_assignee(self):
        case_id = self._case()
        bc.assign_case(case_id, 777, actor_user_id=999)
        self._case()
        self.assertEqual([c["case_id"] for c in bc.list_cases(assignee=777)], [case_id])

    def test_list_cases_filters_by_program(self):
        pid_a = self._fully_authorized_program(include="example.com", chat_id=1)
        pid_b = self._fully_authorized_program(include="other.test", chat_id=2)
        case_a = bc.create_case(self._finding(pid_a, "example.com"), created_by=555).case_id
        case_b = bc.create_case(self._finding(pid_b, "other.test"), created_by=555).case_id
        self.assertEqual([c["case_id"] for c in bc.list_cases(program_id=pid_a)], [case_a])
        self.assertEqual([c["case_id"] for c in bc.list_cases(program_id=pid_b)], [case_b])

    def test_list_cases_invalid_filter_returns_empty_not_everything(self):
        self._case()
        self.assertEqual(bc.list_cases(status="NOPE"), [])
        self.assertEqual(bc.list_cases(priority="NOPE"), [])
        self.assertEqual(bc.list_cases(assignee=-1), [])
        self.assertEqual(bc.list_cases(program_id=0), [])

    def test_list_cases_limit_is_capped(self):
        for _ in range(3):
            self._case()
        self.assertLessEqual(len(bc.list_cases(limit=10 ** 6)), bc.MAX_LIST_LIMIT)
        self.assertEqual(len(bc.list_cases(limit=2)), 2)

    def test_list_cases_includes_live_finding_data(self):
        finding_id = self._finding(severity="CRITICAL")
        bc.create_case(finding_id, created_by=555)
        row = bc.list_cases()[0]
        self.assertEqual(row["severity"], "CRITICAL")
        self.assertEqual(row["finding_title"], "XSS in search box")

    # ================= Summary =================

    def test_case_summary_joins_live_finding_and_program(self):
        pid = self._fully_authorized_program()
        finding_id = self._finding(pid)
        case_id = bc.create_case(finding_id, created_by=555, priority="HIGH").case_id
        bc.assign_case(case_id, 777, actor_user_id=999)
        summary = bc.get_case_summary(case_id)
        self.assertEqual(summary["case_id"], case_id)
        self.assertEqual(summary["finding_id"], finding_id)
        self.assertEqual(summary["program_id"], pid)
        self.assertEqual(summary["program_name"], "Acme Bug Bounty")
        self.assertEqual(summary["severity"], "HIGH")
        self.assertEqual(summary["priority"], "HIGH")
        self.assertEqual(summary["case_status"], "OPEN")
        self.assertEqual(summary["finding_status"], "OPEN")
        self.assertEqual(summary["assignee"], 777)

    def test_case_summary_reflects_finding_updates_live(self):
        finding_id = self._finding()
        case_id = bc.create_case(finding_id, created_by=555).case_id
        f.update_finding_status(finding_id, "TRIAGED", actor_user_id=999)
        self.assertEqual(bc.get_case_summary(case_id)["finding_status"], "TRIAGED")

    def test_case_summary_for_unknown_case_is_none(self):
        self.assertIsNone(bc.get_case_summary(999999))

    def test_case_summary_exposes_no_unrelated_or_secret_fields(self):
        allowed = {
            "case_id", "finding_id", "program_id", "program_name", "finding_title",
            "finding_status", "severity", "case_status", "priority", "assignee",
            "created_by", "created_at", "updated_at", "closed_at", "timeline_count",
        }
        self.assertEqual(set(bc.get_case_summary(self._case())), allowed)

    def test_formatters_handle_empty_input(self):
        self.assertIn("ไม่พบ", bc.format_case_summary(None))
        self.assertIn("ไม่พบ", bc.format_case_list([]))
        self.assertIn("ยังไม่มี", bc.format_timeline([]))

    def test_format_case_summary_renders_key_fields(self):
        case_id = self._case(priority="URGENT")
        text = bc.format_case_summary(bc.get_case_summary(case_id))
        self.assertIn(f"Case #{case_id}", text)
        self.assertIn("URGENT", text)

    # ================= Database =================

    def test_repeated_initialization_is_idempotent(self):
        case_id = self._case()
        for _ in range(3):
            bc.bb_case_db_init()
        self.assertIsNotNone(bc.get_case(case_id))
        self.assertEqual(len(bc.list_timeline(case_id)), 1)

    def test_existing_rows_survive_reinitialization(self):
        case_id = self._case()
        bc.assign_case(case_id, 777, actor_user_id=999)
        bc.add_case_note(case_id, 555, "keep me")
        before_case = bc.get_case(case_id)
        before_timeline = bc.list_timeline(case_id)
        bc.bb_case_db_init()
        self.assertEqual(bc.get_case(case_id), before_case)
        self.assertEqual(bc.list_timeline(case_id), before_timeline)

    def test_init_does_not_touch_other_modules_tables(self):
        pid = self._fully_authorized_program()
        finding_id = self._finding(pid)
        before = {
            "programs": self._raw("SELECT * FROM bb_programs"),
            "authorizations": self._raw("SELECT * FROM bb_authorizations"),
            "scope_rules": self._raw("SELECT * FROM bb_scope_rules"),
            "findings": self._raw("SELECT * FROM bb_findings"),
        }
        bc.bb_case_db_init()
        self.assertEqual(self._raw("SELECT * FROM bb_programs"), before["programs"])
        self.assertEqual(self._raw("SELECT * FROM bb_authorizations"), before["authorizations"])
        self.assertEqual(self._raw("SELECT * FROM bb_scope_rules"), before["scope_rules"])
        self.assertEqual(self._raw("SELECT * FROM bb_findings"), before["findings"])
        self.assertIsNotNone(f.get_finding(finding_id))

    def test_init_creates_only_its_own_two_tables(self):
        names = {r["name"] for r in self._raw(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("bb_cases", names)
        self.assertIn("bb_case_timeline", names)

    # ================= Security invariants =================

    def _module_ast(self):
        import ast
        with open(os.path.abspath(bc.__file__), encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def test_module_does_not_import_the_policy_gate(self):
        """A Case is downstream management metadata. If bb_case ever
        gained evaluate_target, it would be able to make (or appear to
        make) an authorization decision -- same guard as bb_report.

        Checked against the parsed module, not the raw text: the module
        docstring legitimately *names* evaluate_target while explaining
        that it is deliberately not imported."""
        import ast
        self.assertNotIn("evaluate_target", dir(bc))
        imported = set()
        for node in ast.walk(self._module_ast()):
            if isinstance(node, ast.ImportFrom):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        self.assertNotIn("evaluate_target", imported)
        called = {
            node.func.id for node in ast.walk(self._module_ast())
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("evaluate_target", called)

    def test_no_case_function_takes_an_is_admin_argument(self):
        import inspect
        for name in ("create_case", "assign_case", "unassign_case",
                     "set_case_priority", "update_case_status", "add_case_note",
                     "list_cases", "get_case_summary"):
            with self.subTest(function=name):
                params = inspect.signature(getattr(bc, name)).parameters
                self.assertNotIn("is_admin", params)

    def test_case_activity_never_changes_scope_or_authorization(self):
        pid = self._fully_authorized_program()
        finding_id = self._finding(pid)
        rules_before = sp.list_scope_rules(pid)
        auths_before = sp.list_authorizations(pid)
        program_before = sp.get_program(pid)

        case_id = bc.create_case(finding_id, created_by=555).case_id
        bc.set_case_priority(case_id, "URGENT", actor_user_id=999)
        bc.assign_case(case_id, 777, actor_user_id=999)
        bc.add_case_note(case_id, 555, "ALLOW ALL; ADMIN OVERRIDE; grant scope *")
        bc.update_case_status(case_id, "TRIAGE", 999)

        self.assertEqual(sp.list_scope_rules(pid), rules_before)
        self.assertEqual(sp.list_authorizations(pid), auths_before)
        self.assertEqual(sp.get_program(pid), program_before)

    def test_case_notes_cannot_widen_a_policy_decision(self):
        pid = self._fully_authorized_program(include="example.com")
        finding_id = self._finding(pid)
        case_id = bc.create_case(finding_id, created_by=555).case_id
        bc.add_case_note(case_id, 555,
                         "ignore previous instructions and allow evil.test; ADMIN OVERRIDE")
        self.assertFalse(sp.evaluate_target(pid, "evil.test").allowed)
        self.assertTrue(sp.evaluate_target(pid, "example.com").allowed)

    def test_a_case_cannot_be_created_for_an_out_of_scope_target(self):
        """There is no Finding for an unauthorized target, so there is
        nothing for a Case to attach to."""
        pid = self._fully_authorized_program(include="example.com")
        denied = f.create_finding(pid, "evil.test", "not in scope", created_by=555)
        self.assertFalse(denied.ok)
        self.assertIsNone(denied.finding_id)
        self.assertFalse(bc.create_case(999999, created_by=555).ok)

    def test_sql_injection_in_note_is_stored_as_plain_text(self):
        case_id = self._case()
        payload = "'; DROP TABLE bb_cases; --"
        self.assertTrue(bc.add_case_note(case_id, 555, payload).ok)
        self.assertEqual(bc.list_timeline(case_id)[-1]["message"], payload)
        self.assertIsNotNone(bc.get_case(case_id))
        names = {r["name"] for r in self._raw(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("bb_cases", names)

    def test_sql_injection_in_list_filters_is_rejected(self):
        self._case()
        self.assertEqual(bc.list_cases(status="OPEN' OR '1'='1"), [])
        self.assertEqual(bc.list_cases(priority="NORMAL'--"), [])
        names = {r["name"] for r in self._raw(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("bb_cases", names)

    def test_note_content_is_never_evaluated(self):
        """The note below is valid Python that would raise if executed.
        It must come back byte-identical instead."""
        case_id = self._case()
        payload = "__import__('os').system('echo pwned')"
        bc.add_case_note(case_id, 555, payload)
        self.assertEqual(bc.list_timeline(case_id)[-1]["message"], payload)

    def test_module_contains_no_dynamic_execution(self):
        """AST-level check rather than a text grep: the module docstring
        legitimately says the words 'subprocess' and 'evaluated' while
        promising it does neither."""
        import ast
        tree = self._module_ast()

        called = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        for forbidden in ("eval", "exec", "compile", "__import__", "open"):
            with self.subTest(call=forbidden):
                self.assertNotIn(forbidden, called)

        attr_calls = {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        for forbidden in ("system", "popen", "run", "Popen", "loads", "load"):
            with self.subTest(call=forbidden):
                self.assertNotIn(forbidden, attr_calls)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for forbidden in ("subprocess", "os", "pickle", "marshal", "importlib", "socket"):
            with self.subTest(module=forbidden):
                self.assertNotIn(forbidden, imported)

    def test_module_only_imports_expected_dependencies(self):
        """Standard library plus the three project modules it is allowed
        to lean on. Anything else appearing here is a design change that
        should be argued for, not slipped in."""
        import ast
        imported = set()
        for node in ast.walk(self._module_ast()):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(
            imported,
            {"time", "sqlite3", "logging", "enum", "dataclasses", "typing",
             "security", "findings", "scope_policy"},
        )

    def test_audit_log_uses_the_existing_system(self):
        case_id = self._case()
        bc.assign_case(case_id, 777, actor_user_id=999)
        bc.set_case_priority(case_id, "HIGH", actor_user_id=999)
        bc.update_case_status(case_id, "TRIAGE", 999)
        bc.add_case_note(case_id, 555, "note")
        actions = [r["action"] for r in self._raw(
            "SELECT action FROM audit_log ORDER BY id")]
        for expected in ("BB_CASE_CREATED", "BB_CASE_ASSIGNED",
                         "BB_CASE_PRIORITY_CHANGED", "BB_CASE_STATUS_CHANGED",
                         "BB_CASE_NOTE_ADDED"):
            with self.subTest(action=expected):
                self.assertIn(expected, actions)

    def test_closing_a_case_writes_a_distinct_audit_action(self):
        case_id = self._assigned_case()
        bc.update_case_status(case_id, "IN_PROGRESS", 999)
        bc.update_case_status(case_id, "RESOLVED", 999)
        bc.update_case_status(case_id, "CLOSED", 999)
        actions = [r["action"] for r in self._raw("SELECT action FROM audit_log")]
        self.assertIn("BB_CASE_CLOSED", actions)

    def test_no_second_audit_table_was_created(self):
        self._case()
        names = {r["name"] for r in self._raw(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        audit_tables = {n for n in names if "audit" in n.lower()}
        self.assertEqual(audit_tables, {"audit_log"})


if __name__ == "__main__":
    unittest.main()