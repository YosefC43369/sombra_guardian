"""
test_member_incident.py — Phase 9 test suite (incidents / evidence /
integrity / chain of custody / admin audit / reporting / authorization).

Same isolation pattern as test_findings.py / test_member_intel.py: each
test gets a fresh, isolated SQLite file (tempfile). Exercises the real
public APIs of member_incident.py and member_report.py, plus app.py's
administrator gate for the whole command family.

Deliberate negative coverage:
  - illegal lifecycle transitions must be refused, ARCHIVED is terminal
  - a tampered evidence row must fail integrity verification
  - a failed moderation attempt must NOT be logged as a success
  - an admin of one group must not be able to read another group's
    incident or evidence by guessing an id
  - a non-admin, and an admin in a private chat, must be refused
  - every rendered report must carry all four mandatory sections
"""

import asyncio
import os
import sqlite3
import tempfile
import unittest

import security
import member_intel as mi
import member_incident as mic
import member_report as mrep

T0 = 1_700_000_000
CHAT = -100
OTHER_CHAT = -200
USER = 555
ADMIN = 777


class MemberIncidentTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        for module in (security, mi, mic):
            module.DB_PATH = path
        security.security_db_init()
        mi.member_intel_db_init()
        mic.member_incident_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers ----

    def _member(self, chat_id=CHAT, user_id=USER, username="alpha", display="Alpha"):
        mi.record_observation(chat_id, user_id, username=username, display_name=display,
                              counts_as_message=True, message_id=1, now=T0)

    def _incident(self, chat_id=CHAT, user_id=USER,
                  category=mic.IncidentCategory.SPAM.value, **kwargs):
        self._member(chat_id, user_id)
        result = mic.create_incident(chat_id, user_id, category, opened_by=ADMIN,
                                     now=T0, **kwargs)
        self.assertTrue(result.ok, result.reason)
        return result.incident_id

    def _evidence(self, incident_id=None, chat_id=CHAT, user_id=USER,
                  content="buy now http://bad.example", **kwargs):
        result = mic.capture_evidence(chat_id, user_id, incident_id=incident_id,
                                      message_id=42, content=content,
                                      username="alpha", display_name="Alpha",
                                      captured_by=ADMIN, now=T0, **kwargs)
        self.assertTrue(result.ok, result.reason)
        return result.evidence_id


# ---------------- Phase 16: database initialization ----------------

class DatabaseInitTests(MemberIncidentTestCase):
    def test_init_creates_every_table(self):
        conn = sqlite3.connect(self._db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        for expected in ("mi_incidents", "mi_incident_notes", "mi_evidence",
                         "mi_custody", "mi_admin_actions"):
            self.assertIn(expected, tables)

    def test_repeated_initialization_is_idempotent(self):
        for _ in range(3):
            mic.member_incident_db_init()
        self.assertIsNotNone(mic.get_incident(self._incident()))

    def test_existing_rows_survive_reinitialization(self):
        incident_id = self._incident()
        evidence_id = self._evidence(incident_id)
        mic.member_incident_db_init()  # simulate a restart re-running init
        self.assertIsNotNone(mic.get_incident(incident_id))
        self.assertIsNotNone(mic.get_evidence(evidence_id))
        self.assertTrue(mic.get_custody_trail(incident_id=incident_id))

    def test_module_has_no_delete_or_update_against_custody(self):
        """The append-only guarantee is a property of the source, so
        assert it there: no UPDATE/DELETE statement against mi_custody
        may exist anywhere in the module."""
        source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "member_incident.py"), encoding="utf-8").read()
        lowered = source.lower()
        self.assertNotIn("delete from mi_custody", lowered)
        self.assertNotIn("update mi_custody", lowered)


# ---------------- Phase 6: incident engine ----------------

class IncidentEngineTests(MemberIncidentTestCase):
    def test_create_incident_records_everything(self):
        incident_id = self._incident(category=mic.IncidentCategory.PHISHING.value,
                                     severity="HIGH", summary="fake bank link",
                                     trigger_rules="detection:BLOCKED_LINK")
        incident = mic.get_incident(incident_id)
        self.assertEqual(incident["status"], mic.IncidentStatus.OPEN.value)
        self.assertEqual(incident["category"], "PHISHING")
        self.assertEqual(incident["severity"], "HIGH")
        self.assertEqual(incident["opened_by"], ADMIN)
        self.assertEqual(incident["username_snapshot"], "alpha")
        self.assertEqual(incident["opened_at"], T0)

    def test_invalid_category_is_refused(self):
        result = mic.create_incident(CHAT, USER, "NOT_A_CATEGORY", opened_by=ADMIN)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_CATEGORY")
        self.assertEqual(mic.list_incidents(CHAT), [])

    def test_invalid_severity_is_refused(self):
        result = mic.create_incident(CHAT, USER, mic.IncidentCategory.SPAM.value,
                                     severity="APOCALYPTIC", opened_by=ADMIN)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_SEVERITY")

    def test_system_opened_incident_has_no_admin(self):
        result = mic.create_incident(CHAT, USER, mic.IncidentCategory.SPAM.value,
                                     opened_by=None, source="SYSTEM", now=T0)
        incident = mic.get_incident(result.incident_id)
        self.assertIsNone(incident["opened_by"])
        self.assertEqual(incident["source"], "SYSTEM")

    def test_incident_creation_writes_timeline_and_custody_and_audit(self):
        incident_id = self._incident()
        types = [e["event_type"] for e in mi.get_timeline(CHAT, USER)]
        self.assertIn(mi.TimelineEvent.INCIDENT_CREATED.value, types)
        actions = [c["action"] for c in mic.get_custody_trail(incident_id=incident_id)]
        self.assertIn(mic.CustodyAction.INCIDENT_CREATED.value, actions)
        audit = [r["action"] for r in security.get_recent_audit_log(CHAT, limit=20)]
        self.assertIn("INCIDENT_CREATED", audit)

    def test_lifecycle_happy_path(self):
        incident_id = self._incident()
        for status in ("UNDER_REVIEW", "CONFIRMED", "ARCHIVED"):
            result = mic.update_incident_status(incident_id, status, ADMIN)
            self.assertTrue(result.ok, f"{status}: {result.reason}")
        self.assertEqual(mic.get_incident(incident_id)["status"], "ARCHIVED")

    def test_dismissed_path_is_allowed(self):
        incident_id = self._incident()
        self.assertTrue(mic.update_incident_status(incident_id, "DISMISSED", ADMIN).ok)
        self.assertTrue(mic.update_incident_status(incident_id, "ARCHIVED", ADMIN).ok)

    def test_illegal_transition_is_refused(self):
        incident_id = self._incident()
        result = mic.update_incident_status(incident_id, "ARCHIVED", ADMIN)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_TRANSITION")
        self.assertEqual(mic.get_incident(incident_id)["status"], "OPEN")

    def test_archived_is_terminal_and_cannot_be_reopened(self):
        incident_id = self._incident()
        mic.update_incident_status(incident_id, "CONFIRMED", ADMIN)
        mic.update_incident_status(incident_id, "ARCHIVED", ADMIN)
        for status in sorted(mic.VALID_INCIDENT_STATUSES):
            result = mic.update_incident_status(incident_id, status, ADMIN)
            self.assertFalse(result.ok, f"{status} must not be reachable from ARCHIVED")
        self.assertEqual(mic.INCIDENT_TRANSITIONS["ARCHIVED"], frozenset())

    def test_same_status_is_no_change(self):
        incident_id = self._incident()
        self.assertEqual(mic.update_incident_status(incident_id, "OPEN", ADMIN).reason,
                         "NO_CHANGE")

    def test_unknown_status_is_refused(self):
        incident_id = self._incident()
        self.assertEqual(
            mic.update_incident_status(incident_id, "WHATEVER", ADMIN).reason,
            "INVALID_STATUS")

    def test_missing_incident_is_refused(self):
        self.assertEqual(mic.update_incident_status(99999, "CONFIRMED", ADMIN).reason,
                         "INCIDENT_NOT_FOUND")
        self.assertIsNone(mic.get_incident(99999))
        self.assertIsNone(mic.get_incident_bundle(99999))

    def test_resolution_records_who_and_when(self):
        incident_id = self._incident()
        mic.update_incident_status(incident_id, "CONFIRMED", ADMIN, now=T0 + 500)
        incident = mic.get_incident(incident_id)
        self.assertEqual(incident["resolved_by"], ADMIN)
        self.assertEqual(incident["resolved_at"], T0 + 500)

    def test_resolution_emits_resolved_timeline_event(self):
        incident_id = self._incident()
        mic.update_incident_status(incident_id, "DISMISSED", ADMIN)
        types = [e["event_type"] for e in mi.get_timeline(CHAT, USER)]
        self.assertIn(mi.TimelineEvent.INCIDENT_RESOLVED.value, types)

    def test_notes_are_stored_and_ordered(self):
        incident_id = self._incident()
        mic.add_incident_note(incident_id, ADMIN, "first look", now=T0 + 1)
        mic.add_incident_note(incident_id, ADMIN, "second look", now=T0 + 2)
        notes = mic.list_incident_notes(incident_id)
        self.assertEqual([n["note"] for n in notes], ["first look", "second look"])

    def test_empty_note_is_refused(self):
        incident_id = self._incident()
        self.assertEqual(mic.add_incident_note(incident_id, ADMIN, "   ").reason,
                         "EMPTY_NOTE")

    def test_note_on_missing_incident_is_refused(self):
        self.assertEqual(mic.add_incident_note(99999, ADMIN, "hi").reason,
                         "INCIDENT_NOT_FOUND")

    def test_listing_filters_are_validated(self):
        self._incident(category=mic.IncidentCategory.SPAM.value)
        self._incident(user_id=2, category=mic.IncidentCategory.PHISHING.value)
        self.assertEqual(len(mic.list_incidents(CHAT)), 2)
        self.assertEqual(len(mic.list_incidents(CHAT, category="PHISHING")), 1)
        self.assertEqual(len(mic.list_incidents(CHAT, status="OPEN")), 2)
        self.assertEqual(mic.list_incidents(CHAT, status="BOGUS"), [])
        self.assertEqual(mic.list_incidents(CHAT, category="BOGUS"), [])

    def test_open_only_excludes_resolved(self):
        first = self._incident()
        second = self._incident(user_id=2)
        mic.update_incident_status(second, "DISMISSED", ADMIN)
        open_ids = [i["incident_id"] for i in mic.list_incidents(CHAT, open_only=True)]
        self.assertEqual(open_ids, [first])

    def test_listing_is_scoped_to_one_chat(self):
        self._incident(chat_id=CHAT)
        self._incident(chat_id=OTHER_CHAT, user_id=9)
        self.assertEqual(len(mic.list_incidents(CHAT)), 1)

    def test_stats_group_by_status_category_severity(self):
        self._incident(severity="HIGH")
        self._incident(user_id=2, category=mic.IncidentCategory.SCAM.value)
        stats = mic.get_incident_stats(CHAT)
        self.assertEqual(stats["by_status"]["OPEN"], 2)
        self.assertEqual(stats["by_category"]["SCAM"], 1)
        self.assertEqual(stats["by_severity"]["HIGH"], 1)


# ---------------- Automatic incident creation from detection ----------------

class AutoIncidentTests(MemberIncidentTestCase):
    def test_high_severity_detection_opens_incident_with_evidence(self):
        self._member()
        result = mic.incident_from_detection(
            CHAT, USER, "BLOCKED_LINK", "high", reason="suspicious link",
            message_id=42, content="click http://bad.example",
            username="alpha", display_name="Alpha", now=T0)
        self.assertTrue(result.ok)
        incident = mic.get_incident(result.incident_id)
        self.assertEqual(incident["category"], "MALICIOUS_LINK")
        self.assertEqual(incident["severity"], "HIGH")
        self.assertIsNone(incident["opened_by"])  # the bot opened it
        self.assertEqual(incident["source"], "SYSTEM")
        evidence = mic.list_evidence(incident_id=result.incident_id)
        self.assertEqual(len(evidence), 1)
        self.assertIn("bad.example", evidence[0]["content_snapshot"])

    def test_low_severity_is_below_threshold(self):
        result = mic.incident_from_detection(CHAT, USER, "SPAM", "low", now=T0)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "BELOW_SEVERITY_THRESHOLD")
        self.assertEqual(mic.list_incidents(CHAT), [])

    def test_unmapped_detection_type_is_not_guessed(self):
        result = mic.incident_from_detection(CHAT, USER, "SOMETHING_NEW", "high", now=T0)
        self.assertTrue(result.ok)
        self.assertEqual(mic.get_incident(result.incident_id)["category"],
                         mic.IncidentCategory.OTHER_SECURITY_EVENT.value)

    def test_burst_is_deduped_into_one_incident(self):
        self._member()
        first = mic.incident_from_detection(CHAT, USER, "SPAM", "high",
                                            message_id=1, content="spam", now=T0)
        for i in range(2, 6):
            again = mic.incident_from_detection(CHAT, USER, "SPAM", "high",
                                                 message_id=i, content="spam", now=T0 + i)
            self.assertEqual(again.reason, "APPENDED_TO_EXISTING")
            self.assertEqual(again.incident_id, first.incident_id)
        self.assertEqual(len(mic.list_incidents(CHAT)), 1)
        self.assertEqual(len(mic.list_evidence(incident_id=first.incident_id)), 5)

    def test_different_categories_open_separate_incidents(self):
        self._member()
        a = mic.incident_from_detection(CHAT, USER, "SPAM", "high", now=T0)
        b = mic.incident_from_detection(CHAT, USER, "BLOCKED_LINK", "high", now=T0)
        self.assertNotEqual(a.incident_id, b.incident_id)

    def test_resolved_incident_does_not_absorb_new_detections(self):
        self._member()
        first = mic.incident_from_detection(CHAT, USER, "SPAM", "high", now=T0)
        mic.update_incident_status(first.incident_id, "DISMISSED", ADMIN)
        second = mic.incident_from_detection(CHAT, USER, "SPAM", "high", now=T0 + 10)
        self.assertNotEqual(second.incident_id, first.incident_id)

    def test_dedupe_window_expires(self):
        self._member()
        first = mic.incident_from_detection(CHAT, USER, "SPAM", "high", now=T0)
        later = mic.incident_from_detection(
            CHAT, USER, "SPAM", "high",
            now=T0 + mic.AUTO_INCIDENT_DEDUPE_SECONDS + 60)
        self.assertNotEqual(later.incident_id, first.incident_id)

    def test_auto_incident_can_be_disabled(self):
        mic.AUTO_INCIDENT_ENABLED = False
        try:
            result = mic.incident_from_detection(CHAT, USER, "SPAM", "high", now=T0)
            self.assertFalse(result.ok)
            self.assertEqual(result.reason, "AUTO_INCIDENT_DISABLED")
            self.assertEqual(mic.list_incidents(CHAT), [])
        finally:
            mic.AUTO_INCIDENT_ENABLED = True


# ---------------- Phase 7/8: evidence vault + integrity ----------------

class EvidenceVaultTests(MemberIncidentTestCase):
    def test_evidence_stores_snapshots_and_hash(self):
        incident_id = self._incident()
        evidence_id = self._evidence(incident_id)
        record = mic.get_evidence(evidence_id)
        self.assertEqual(record["username_snapshot"], "alpha")
        self.assertEqual(record["display_name_snapshot"], "Alpha")
        self.assertEqual(record["message_id"], 42)
        self.assertEqual(record["captured_at"], T0)
        self.assertEqual(len(record["sha256"]), 64)
        self.assertIn("bad.example", record["content_snapshot"])

    def test_snapshot_survives_a_later_rename(self):
        """The whole point of the vault: renaming the account afterwards
        must not rewrite what the evidence says it was called."""
        incident_id = self._incident()
        evidence_id = self._evidence(incident_id)
        mi.record_observation(CHAT, USER, username="totally_new",
                              display_name="New Name", now=T0 + 10_000)
        record = mic.get_evidence(evidence_id)
        self.assertEqual(record["username_snapshot"], "alpha")
        self.assertEqual(mi.get_member(CHAT, USER)["username"], "totally_new")
        # and the snapshot still verifies -- the rename changed nothing here
        self.assertTrue(mic.verify_evidence(evidence_id).match)

    def test_snapshot_falls_back_to_registry_when_not_supplied(self):
        self._member()
        result = mic.capture_evidence(CHAT, USER, content="hi", now=T0)
        self.assertEqual(mic.get_evidence(result.evidence_id)["username_snapshot"],
                         "alpha")

    def test_evidence_without_incident_is_allowed(self):
        self._member()
        evidence_id = self._evidence(incident_id=None)
        self.assertIsNone(mic.get_evidence(evidence_id)["incident_id"])

    def test_evidence_for_missing_incident_is_refused(self):
        result = mic.capture_evidence(CHAT, USER, incident_id=99999, content="x")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INCIDENT_NOT_FOUND")

    def test_invalid_kind_is_refused(self):
        result = mic.capture_evidence(CHAT, USER, kind="MADE_UP", content="x")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_EVIDENCE_KIND")

    def test_absent_content_is_explained_not_blank(self):
        self._member()
        result = mic.capture_evidence(CHAT, USER, content=None,
                                      media_kind="photo",
                                      media_file_unique_id="AgADBAAD", now=T0)
        record = mic.get_evidence(result.evidence_id)
        self.assertIsNone(record["content_snapshot"])
        self.assertEqual(record["content_omitted_reason"], "NO_TEXT_CONTENT")
        self.assertEqual(record["media_kind"], "photo")

    def test_content_retention_can_be_disabled(self):
        mic.STORE_MESSAGE_CONTENT = False
        try:
            self._member()
            result = mic.capture_evidence(CHAT, USER, content="sensitive text", now=T0)
            record = mic.get_evidence(result.evidence_id)
            self.assertIsNone(record["content_snapshot"])
            self.assertEqual(record["content_omitted_reason"],
                             "CONTENT_RETENTION_DISABLED")
            # structural facts are still recorded, and still hashed
            self.assertEqual(record["user_id"], USER)
            self.assertTrue(mic.verify_evidence(result.evidence_id).match)
        finally:
            mic.STORE_MESSAGE_CONTENT = True

    def test_overlong_content_is_truncated_and_flagged(self):
        self._member()
        result = mic.capture_evidence(CHAT, USER,
                                      content="x" * (mic.MAX_CONTENT_SNAPSHOT_LEN + 500),
                                      now=T0)
        record = mic.get_evidence(result.evidence_id)
        self.assertEqual(len(record["content_snapshot"]), mic.MAX_CONTENT_SNAPSHOT_LEN)
        self.assertIn("TRUNCATED", record["content_omitted_reason"])

    def test_listing_requires_a_scope(self):
        self._member()
        self._evidence()
        self.assertEqual(mic.list_evidence(), [])
        self.assertEqual(len(mic.list_evidence(chat_id=CHAT)), 1)

    def test_listing_is_scoped_to_one_chat(self):
        self._member()
        self._evidence()
        mi.record_observation(OTHER_CHAT, 9, username="z", now=T0)
        mic.capture_evidence(OTHER_CHAT, 9, content="other group", now=T0)
        self.assertEqual(len(mic.list_evidence(chat_id=CHAT)), 1)
        self.assertEqual(len(mic.list_evidence(chat_id=OTHER_CHAT)), 1)

    def test_missing_evidence_reads_as_none(self):
        self.assertIsNone(mic.get_evidence(99999))


class EvidenceIntegrityTests(MemberIncidentTestCase):
    def test_hash_is_deterministic_for_identical_records(self):
        self._member()
        first = mic.capture_evidence(CHAT, USER, message_id=1, content="same",
                                     username="alpha", display_name="Alpha", now=T0)
        second = mic.capture_evidence(CHAT, USER, message_id=1, content="same",
                                      username="alpha", display_name="Alpha", now=T0)
        self.assertEqual(first.sha256, second.sha256)

    def test_hash_differs_when_content_differs(self):
        self._member()
        first = mic.capture_evidence(CHAT, USER, content="a", now=T0)
        second = mic.capture_evidence(CHAT, USER, content="b", now=T0)
        self.assertNotEqual(first.sha256, second.sha256)

    def test_verification_passes_for_untouched_record(self):
        evidence_id = self._evidence(self._incident())
        result = mic.verify_evidence(evidence_id, actor_user_id=ADMIN)
        self.assertTrue(result.ok)
        self.assertTrue(result.match)
        self.assertEqual(result.stored_sha256, result.recalculated_sha256)

    def test_verification_detects_tampered_content(self):
        evidence_id = self._evidence(self._incident())
        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE mi_evidence SET content_snapshot='innocent' "
                     "WHERE evidence_id=?", (evidence_id,))
        conn.commit()
        conn.close()
        result = mic.verify_evidence(evidence_id, actor_user_id=ADMIN)
        self.assertTrue(result.ok)
        self.assertFalse(result.match)

    def test_verification_detects_tampered_username_snapshot(self):
        evidence_id = self._evidence(self._incident())
        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE mi_evidence SET username_snapshot='someone_else' "
                     "WHERE evidence_id=?", (evidence_id,))
        conn.commit()
        conn.close()
        self.assertFalse(mic.verify_evidence(evidence_id).match)

    def test_verification_detects_tampered_timestamp(self):
        evidence_id = self._evidence(self._incident())
        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE mi_evidence SET captured_at=? WHERE evidence_id=?",
                     (T0 + 99999, evidence_id))
        conn.commit()
        conn.close()
        self.assertFalse(mic.verify_evidence(evidence_id).match)

    def test_verifying_does_not_change_the_hash(self):
        """last_verified_at/last_verify_result are excluded from the
        hashed fields on purpose: checking evidence must not invalidate
        it, or a second check would always fail."""
        evidence_id = self._evidence(self._incident())
        self.assertTrue(mic.verify_evidence(evidence_id).match)
        self.assertTrue(mic.verify_evidence(evidence_id).match)
        self.assertTrue(mic.verify_evidence(evidence_id).match)

    def test_verification_result_is_recorded_on_the_row(self):
        evidence_id = self._evidence(self._incident())
        mic.verify_evidence(evidence_id, actor_user_id=ADMIN, now=T0 + 60)
        record = mic.get_evidence(evidence_id)
        self.assertEqual(record["last_verify_result"], "MATCH")
        self.assertEqual(record["last_verified_at"], T0 + 60)

    def test_verification_of_missing_record(self):
        result = mic.verify_evidence(99999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "EVIDENCE_NOT_FOUND")

    def test_verification_without_stored_hash(self):
        evidence_id = self._evidence(self._incident())
        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE mi_evidence SET sha256='' WHERE evidence_id=?",
                     (evidence_id,))
        conn.commit()
        conn.close()
        self.assertEqual(mic.verify_evidence(evidence_id).reason, "NO_STORED_HASH")

    def test_bulk_verification_summarises(self):
        incident_id = self._incident()
        good = self._evidence(incident_id, content="one")
        bad = self._evidence(incident_id, content="two")
        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE mi_evidence SET content_snapshot='x' WHERE evidence_id=?",
                     (bad,))
        conn.commit()
        conn.close()
        summary = mic.verify_incident_evidence(incident_id, actor_user_id=ADMIN)
        self.assertEqual(summary["checked"], 2)
        self.assertEqual(summary["intact"], 1)
        self.assertEqual(summary["mismatched"], 1)
        self.assertIn("ไม่ได้พิสูจน์ว่าใครเป็นผู้สร้าง", summary["disclaimer"])
        self.assertIn(good, [r["evidence_id"] for r in summary["results"]])


# ---------------- Phase 9: chain of custody ----------------

class ChainOfCustodyTests(MemberIncidentTestCase):
    def test_full_lifecycle_is_reconstructable(self):
        incident_id = self._incident()
        evidence_id = self._evidence(incident_id)
        mic.mark_evidence_reviewed(evidence_id, ADMIN, note="looked at it", now=T0 + 10)
        mic.verify_evidence(evidence_id, actor_user_id=ADMIN, now=T0 + 20)
        mic.mark_evidence_exported([evidence_id], ADMIN, destination="csv", now=T0 + 30)
        actions = [c["action"] for c in mic.get_custody_trail(evidence_id=evidence_id,
                                                              limit=50)]
        self.assertEqual(actions, [
            mic.CustodyAction.EVIDENCE_CREATED.value,
            mic.CustodyAction.EVIDENCE_LINKED.value,
            mic.CustodyAction.EVIDENCE_REVIEWED.value,
            mic.CustodyAction.EVIDENCE_VERIFIED.value,
            mic.CustodyAction.EVIDENCE_EXPORTED.value,
        ])

    def test_trail_is_oldest_first(self):
        incident_id = self._incident()
        evidence_id = self._evidence(incident_id)
        mic.verify_evidence(evidence_id, now=T0 + 100)
        rows = mic.get_custody_trail(evidence_id=evidence_id, limit=50)
        stamps = [r["created_at"] for r in rows]
        self.assertEqual(stamps, sorted(stamps))

    def test_actor_kind_distinguishes_bot_from_admin(self):
        self._member()
        system = mic.incident_from_detection(CHAT, USER, "SPAM", "high", now=T0)
        rows = mic.get_custody_trail(incident_id=system.incident_id, limit=50)
        self.assertTrue(all(r["actor_kind"] == "system" for r in rows))
        self.assertTrue(all(r["actor_user_id"] is None for r in rows))

        mic.update_incident_status(system.incident_id, "CONFIRMED", ADMIN, now=T0 + 10)
        rows = mic.get_custody_trail(incident_id=system.incident_id, limit=50)
        admin_rows = [r for r in rows if r["actor_kind"] == "user"]
        self.assertTrue(admin_rows)
        self.assertTrue(all(r["actor_user_id"] == ADMIN for r in admin_rows))

    def test_unknown_custody_action_is_rejected(self):
        self.assertIsNone(mic.add_custody_event("SOMETHING_ELSE", incident_id=1))

    def test_trail_requires_a_scope(self):
        self._incident()
        self.assertEqual(mic.get_custody_trail(), [])

    def test_export_of_missing_evidence_is_skipped(self):
        self.assertEqual(mic.mark_evidence_exported([99999], ADMIN), 0)

    def test_review_of_missing_evidence_is_false(self):
        self.assertFalse(mic.mark_evidence_reviewed(99999, ADMIN))


# ---------------- Phase 10: admin action audit ----------------

class AdminAuditTests(MemberIncidentTestCase):
    def test_action_records_admin_and_target(self):
        mic.record_admin_action(CHAT, mic.AdminAction.BANNED, target_user_id=USER,
                                admin_user_id=ADMIN, reason="repeated spam", now=T0)
        row = mic.list_admin_actions(CHAT)[0]
        self.assertEqual(row["action"], "BANNED")
        self.assertEqual(row["admin_user_id"], ADMIN)
        self.assertEqual(row["target_user_id"], USER)
        self.assertEqual(row["executed"], 1)

    def test_bot_action_has_no_admin(self):
        mic.record_admin_action(CHAT, mic.AdminAction.MESSAGE_DELETED,
                                target_user_id=USER, admin_user_id=None, now=T0)
        self.assertIsNone(mic.list_admin_actions(CHAT)[0]["admin_user_id"])

    def test_failed_attempt_is_not_logged_as_success(self):
        """A restriction Telegram refused must be recorded as an attempt,
        never as a completed action."""
        mic.record_admin_action(CHAT, mic.AdminAction.MUTED, target_user_id=USER,
                                admin_user_id=ADMIN, executed=False,
                                reason="no permission", now=T0)
        self.assertEqual(mic.list_admin_actions(CHAT)[0]["executed"], 0)

    def test_unknown_action_is_rejected(self):
        self.assertIsNone(mic.record_admin_action(CHAT, "DO_SOMETHING_WEIRD"))
        self.assertEqual(mic.list_admin_actions(CHAT), [])

    def test_action_also_writes_the_global_audit_log(self):
        mic.record_admin_action(CHAT, mic.AdminAction.BANNED, target_user_id=USER,
                                admin_user_id=ADMIN, now=T0)
        actions = [r["action"] for r in security.get_recent_audit_log(CHAT, limit=10)]
        self.assertIn("ADMIN_BANNED", actions)

    def test_actions_are_filterable(self):
        mic.record_admin_action(CHAT, mic.AdminAction.WARNING, target_user_id=1,
                                admin_user_id=ADMIN, now=T0)
        mic.record_admin_action(CHAT, mic.AdminAction.BANNED, target_user_id=2,
                                admin_user_id=888, now=T0 + 1)
        self.assertEqual(len(mic.list_admin_actions(CHAT, target_user_id=1)), 1)
        self.assertEqual(len(mic.list_admin_actions(CHAT, admin_user_id=888)), 1)
        self.assertEqual(len(mic.list_admin_actions(CHAT, since=T0 + 1)), 1)

    def test_actions_are_scoped_to_one_chat(self):
        mic.record_admin_action(CHAT, mic.AdminAction.WARNING, target_user_id=1, now=T0)
        mic.record_admin_action(OTHER_CHAT, mic.AdminAction.WARNING, target_user_id=1,
                                now=T0)
        self.assertEqual(len(mic.list_admin_actions(CHAT)), 1)

    def test_status_change_records_an_admin_action(self):
        incident_id = self._incident()
        mic.update_incident_status(incident_id, "CONFIRMED", ADMIN, now=T0 + 5)
        actions = mic.list_admin_actions(CHAT, incident_id=incident_id)
        self.assertTrue(any(a["action"] == "INCIDENT_STATUS_CHANGED" for a in actions))


# ---------------- Phase 12: case linking ----------------

class CaseLinkTests(MemberIncidentTestCase):
    def test_missing_case_is_refused(self):
        import scope_policy as sp
        import findings as f
        import bb_case as bc
        for module in (sp, f, bc):
            module.DB_PATH = self._db_path
        sp.scope_policy_db_init()
        f.findings_db_init()
        bc.bb_case_db_init()

        incident_id = self._incident()
        result = mic.link_case(incident_id, 4242, ADMIN)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "CASE_NOT_FOUND")
        self.assertIsNone(mic.get_incident(incident_id)["bb_case_id"])

    def test_existing_case_is_linked_and_audited(self):
        import scope_policy as sp
        import findings as f
        import bb_case as bc
        for module in (sp, f, bc):
            module.DB_PATH = self._db_path
        sp.scope_policy_db_init()
        f.findings_db_init()
        bc.bb_case_db_init()

        program_id = sp.create_program(CHAT, "Prog", created_by=ADMIN)
        sp.set_program_status(program_id, sp.ProgramStatus.ACTIVE.value, ADMIN)
        auth_id = sp.import_authorization(
            program_id, source_type="email", actor_user_id=ADMIN,
            source_reference="sec@example.com", authorization_reference="REF-1")
        sp.review_authorization(auth_id, approve=True, reviewer_user_id=1000)
        sp.add_scope_rule(program_id, sp.RuleType.INCLUDE.value,
                          sp.TargetType.DOMAIN.value, "example.com",
                          actor_user_id=ADMIN)
        finding = f.create_finding(program_id, "example.com", "Title", created_by=ADMIN)
        self.assertTrue(finding.ok, finding.reason)
        case_id = bc.create_case(finding.finding_id, created_by=ADMIN).case_id

        incident_id = self._incident()
        result = mic.link_case(incident_id, case_id, ADMIN)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(mic.get_incident(incident_id)["bb_case_id"], case_id)
        actions = [c["action"] for c in mic.get_custody_trail(incident_id=incident_id)]
        self.assertIn(mic.CustodyAction.INCIDENT_CASE_LINKED.value, actions)

    def test_link_on_missing_incident_is_refused(self):
        self.assertEqual(mic.link_case(99999, 1, ADMIN).reason, "INCIDENT_NOT_FOUND")


# ---------------- Phase 13: reporting & export ----------------

FOUR_SECTIONS = (mrep.SECTION_FACTS, mrep.SECTION_ANALYSIS,
                 mrep.SECTION_ACTIONS, mrep.SECTION_LIMITS)


class ReportingTests(MemberIncidentTestCase):
    def _assert_four_sections(self, text):
        for section in FOUR_SECTIONS:
            self.assertIn(section, text, f"report is missing section: {section}")
        # the Bot API limits must be spelled out, every time
        self.assertIn("ไม่ให้ IP address", text)

    def test_member_activity_report_has_four_sections(self):
        incident_id = self._incident()
        self._evidence(incident_id)
        security.record_event(CHAT, USER, security.SecurityEvent.SPAM, "x")
        text = mrep.format_member_activity_report(
            mrep.get_member_activity_data(CHAT, USER))
        self._assert_four_sections(text)
        self.assertIn("ไม่ใช่ข้อพิสูจน์", text)  # risk disclaimer

    def test_report_for_unknown_member_says_not_observed(self):
        text = mrep.format_member_activity_report(
            mrep.get_member_activity_data(CHAT, 4242))
        self._assert_four_sections(text)
        self.assertIn("ไม่เคยสังเกตเห็น", text)

    def test_risk_report_has_four_sections(self):
        self._member()
        security.record_event(CHAT, USER, security.SecurityEvent.MUTE, "x")
        text = mrep.format_member_risk_report(mrep.get_member_risk_data(CHAT))
        self._assert_four_sections(text)

    def test_single_risk_report_has_four_sections(self):
        self._member()
        assessment = mi.assess_risk(CHAT, USER)
        self._assert_four_sections(mrep.format_single_risk_report(USER, assessment))

    def test_identity_history_report_has_four_sections(self):
        self._member()
        mi.record_observation(CHAT, USER, username="beta", display_name="Alpha",
                              now=T0 + 100)
        text = mrep.format_identity_history_report(CHAT, USER)
        self._assert_four_sections(text)
        self.assertIn("alpha", text)
        self.assertIn("beta", text)

    def test_timeline_report_has_four_sections(self):
        self._member()
        mi.add_timeline_event(CHAT, USER, mi.TimelineEvent.BANNED, actor_user_id=ADMIN,
                              now=T0 + 1)
        self._assert_four_sections(mrep.format_timeline_report(CHAT, USER))

    def test_incident_report_has_four_sections_and_custody(self):
        incident_id = self._incident()
        evidence_id = self._evidence(incident_id)
        mic.verify_evidence(evidence_id, actor_user_id=ADMIN)
        mic.add_incident_note(incident_id, ADMIN, "under review", now=T0 + 5)
        mic.update_incident_status(incident_id, "UNDER_REVIEW", ADMIN, now=T0 + 6)
        text = mrep.format_incident_report(mic.get_incident_bundle(incident_id))
        self._assert_four_sections(text)
        self.assertIn("Chain of Custody", text)
        self.assertIn("under review", text)
        self.assertIn("ไม่ใช่ข้อสรุปว่าผู้ใช้กระทำผิด", text)

    def test_incident_list_report_has_four_sections(self):
        self._incident()
        text = mrep.format_incident_list(CHAT, mic.list_incidents(CHAT),
                                          mic.get_incident_stats(CHAT))
        self._assert_four_sections(text)

    def test_evidence_report_has_four_sections(self):
        incident_id = self._incident()
        evidence_id = self._evidence(incident_id)
        record = mic.get_evidence(evidence_id)
        custody = mic.get_custody_trail(evidence_id=evidence_id, limit=50)
        text = mrep.format_evidence_report(record, custody)
        self._assert_four_sections(text)
        self.assertIn(record["sha256"], text)

    def test_integrity_report_states_match_or_mismatch(self):
        evidence_id = self._evidence(self._incident())
        ok_text = mrep.format_integrity_result(
            evidence_id, mic.verify_evidence(evidence_id))
        self.assertIn("ตรงกัน", ok_text)
        self._assert_four_sections(ok_text)

        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE mi_evidence SET content_snapshot='x' WHERE evidence_id=?",
                     (evidence_id,))
        conn.commit()
        conn.close()
        bad_text = mrep.format_integrity_result(
            evidence_id, mic.verify_evidence(evidence_id))
        self.assertIn("ไม่ตรงกัน", bad_text)

    def test_admin_audit_report_has_four_sections(self):
        mic.record_admin_action(CHAT, mic.AdminAction.BANNED, target_user_id=USER,
                                admin_user_id=ADMIN, now=T0)
        text = mrep.format_admin_audit_report(CHAT, mic.list_admin_actions(CHAT))
        self._assert_four_sections(text)

    def test_pattern_report_never_asserts_same_person(self):
        for user in (1, 2, 3):
            mi.record_message_pattern(CHAT, user, "identical promo", now=T0)
        data = mi.find_correlated_activity(CHAT, min_accounts=3, now=T0 + 10)
        text = mrep.format_pattern_report(data)
        self._assert_four_sections(text)
        self.assertIn("ต้องให้ผู้ดูแลตรวจสอบ", text)
        self.assertIn("ไม่ใช่ข้อพิสูจน์", text)
        self.assertIn("ไม่สามารถและไม่พยายามสรุปว่าบัญชีต่าง ๆ เป็นบุคคลเดียวกัน", text)

    def test_json_export_separates_facts_from_analysis(self):
        import json
        incident_id = self._incident()
        self._evidence(incident_id)
        payload = json.loads(mrep.export_member_json(CHAT, USER))
        for key in ("observed_facts", "system_analysis", "administrative_actions",
                    "limitations"):
            self.assertIn(key, payload)
        self.assertIn("risk", payload["system_analysis"])
        self.assertIn("timeline", payload["observed_facts"])
        self.assertIn("incidents", payload["administrative_actions"])
        self.assertTrue(payload["limitations"])

    def test_json_export_of_unknown_member_is_still_valid(self):
        import json
        payload = json.loads(mrep.export_member_json(CHAT, 4242))
        self.assertFalse(payload["observed_facts"]["known_to_bot"])

    def test_timeline_csv_export(self):
        self._member()
        mi.add_timeline_event(CHAT, USER, mi.TimelineEvent.BANNED, actor_user_id=ADMIN,
                              now=T0 + 1)
        csv_text = mrep.export_timeline_csv(CHAT, USER)
        self.assertTrue(csv_text.startswith("created_at_utc,event_type"))
        self.assertIn("BANNED", csv_text)

    def test_incident_csv_export(self):
        self._incident(severity="HIGH")
        csv_text = mrep.export_incident_csv(CHAT)
        self.assertIn("incident_id,opened_at_utc", csv_text)
        self.assertIn("HIGH", csv_text)

    def test_evidence_csv_export_reports_content_presence(self):
        incident_id = self._incident()
        self._evidence(incident_id)
        csv_text = mrep.export_evidence_csv(CHAT, incident_id=incident_id)
        self.assertIn("evidence_id,incident_id", csv_text)
        self.assertIn("yes", csv_text)

    def test_csv_newlines_do_not_break_rows(self):
        """A newline inside a detail field must not split the CSV row --
        otherwise an attacker-controlled message could forge extra rows
        in an exported report."""
        self._member()  # emits FIRST_MESSAGE
        mi.add_timeline_event(CHAT, USER, mi.TimelineEvent.WARNING_ISSUED,
                              detail="line one\nline two", now=T0)
        csv_text = mrep.export_timeline_csv(CHAT, USER)
        rows = [r for r in csv_text.strip().split("\n") if r]
        self.assertEqual(len(rows), 3)  # header + FIRST_MESSAGE + WARNING_ISSUED
        warning_row = next(r for r in rows if "WARNING_ISSUED" in r)
        self.assertIn("line one line two", warning_row)

    def test_unavailable_timestamps_render_as_unavailable(self):
        self._member()
        text = mrep.format_member_activity_report(
            mrep.get_member_activity_data(CHAT, USER))
        self.assertIn(mi.UNAVAILABLE, text)  # never joined -> joined_at unknown


# ---------------- Phase 15/18: authorization boundaries ----------------

class _FakeUser:
    def __init__(self, user_id, username="admin", full_name="Admin", is_bot=False):
        self.id = user_id
        self.username = username
        self.full_name = full_name
        self.is_bot = is_bot


class _FakeChat:
    def __init__(self, chat_id, chat_type):
        self.id = chat_id
        self.type = chat_type


class _FakeMessage:
    def __init__(self):
        self.replies = []
        self.reply_to_message = None
        self.message_id = 1

    async def reply_text(self, text, **kwargs):
        self.replies.append(text)

    async def reply_document(self, document=None, filename=None, caption=None, **kwargs):
        self.replies.append(f"DOC:{filename}")


class _FakeUpdate:
    def __init__(self, chat, user, message):
        self.effective_chat = chat
        self.effective_user = user
        self.effective_message = message
        self.message = message


class _FakeBot:
    def __init__(self, status):
        self._status = status

    async def get_chat_member(self, chat_id, user_id):
        class _Member:
            status = self._status
        member = _Member()
        member.status = self._status
        return member


class _FakeContext:
    def __init__(self, status="member", args=None):
        self.bot = _FakeBot(status)
        self.args = args or []


class AuthorizationTests(MemberIncidentTestCase):
    """Every command in this family must be refused unless the caller is
    a real Telegram administrator of the group the command runs in.

    The private-chat case matters specifically: is_admin() asks Telegram
    for the caller's status in effective_chat, which in a private chat is
    the caller's own chat -- so a private-chat path would be asking a
    meaningless question. The gate rejects it before that happens."""

    def setUp(self):
        super().setUp()
        import app
        self.app = app
        for module in (app.mi, app.mic):
            module.DB_PATH = self._db_path

    def _run(self, coro):
        return asyncio.run(coro)

    def _update(self, chat_type="supergroup", chat_id=CHAT, user_id=ADMIN):
        message = _FakeMessage()
        return _FakeUpdate(_FakeChat(chat_id, chat_type), _FakeUser(user_id), message), message

    ADMIN_COMMANDS = (
        "cmd_member", "cmd_memberhistory", "cmd_memberrisk", "cmd_timeline",
        "cmd_incidents", "cmd_incident", "cmd_evidence", "cmd_verifyevidence",
        "cmd_memberreport", "cmd_memberpatterns", "cmd_memberpurge",
    )

    def test_non_admin_is_refused_by_every_command(self):
        for name in self.ADMIN_COMMANDS:
            update, message = self._update()
            context = _FakeContext(status="member", args=["1"])
            self._run(getattr(self.app, name)(update, context))
            self.assertEqual(message.replies, [self.app.MEMBER_ADMIN_ONLY_TEXT],
                             f"{name} did not refuse a non-admin")

    def test_private_chat_is_refused_by_every_command(self):
        for name in self.ADMIN_COMMANDS:
            update, message = self._update(chat_type="private")
            context = _FakeContext(status="administrator", args=["1"])
            self._run(getattr(self.app, name)(update, context))
            self.assertEqual(message.replies, [self.app.MEMBER_GROUP_ONLY_TEXT],
                             f"{name} did not refuse a private chat")

    def test_admin_is_allowed_through(self):
        self._member()
        update, message = self._update()
        context = _FakeContext(status="administrator", args=[str(USER)])
        self._run(self.app.cmd_member(update, context))
        self.assertTrue(message.replies)
        self.assertNotIn(self.app.MEMBER_ADMIN_ONLY_TEXT, message.replies)
        self.assertIn(mrep.SECTION_FACTS, "\n".join(message.replies))

    def test_owner_is_allowed_through(self):
        self._member()
        update, message = self._update()
        context = _FakeContext(status="creator", args=[str(USER)])
        self._run(self.app.cmd_member(update, context))
        self.assertIn(mrep.SECTION_FACTS, "\n".join(message.replies))

    def test_admin_cannot_read_another_groups_incident(self):
        """Cross-tenant isolation: ids are sequential integers, so an
        admin of one group must not be able to page through another
        group's incidents by guessing."""
        other_incident = self._incident(chat_id=OTHER_CHAT, user_id=9)
        update, message = self._update(chat_id=CHAT)
        context = _FakeContext(status="administrator", args=[str(other_incident)])
        self._run(self.app.cmd_incident(update, context))
        self.assertIn("ไม่ได้อยู่ในกลุ่มนี้", "\n".join(message.replies))

    def test_admin_cannot_read_another_groups_evidence(self):
        other_incident = self._incident(chat_id=OTHER_CHAT, user_id=9)
        other_evidence = self._evidence(other_incident, chat_id=OTHER_CHAT, user_id=9)
        update, message = self._update(chat_id=CHAT)
        context = _FakeContext(status="administrator", args=[str(other_evidence)])
        self._run(self.app.cmd_evidence(update, context))
        self.assertIn("ไม่พบหลักฐาน", "\n".join(message.replies))

    def test_admin_cannot_verify_another_groups_evidence(self):
        other_incident = self._incident(chat_id=OTHER_CHAT, user_id=9)
        other_evidence = self._evidence(other_incident, chat_id=OTHER_CHAT, user_id=9)
        update, message = self._update(chat_id=CHAT)
        context = _FakeContext(status="administrator", args=[str(other_evidence)])
        self._run(self.app.cmd_verifyevidence(update, context))
        self.assertIn("ไม่พบหลักฐาน", "\n".join(message.replies))

    def test_admin_cannot_link_another_groups_incident(self):
        other_incident = self._incident(chat_id=OTHER_CHAT, user_id=9)
        update, message = self._update(chat_id=CHAT)
        context = _FakeContext(status="administrator",
                               args=[str(other_incident), "status", "CONFIRMED"])
        self._run(self.app.cmd_incident(update, context))
        self.assertIn("ไม่ได้อยู่ในกลุ่มนี้", "\n".join(message.replies))
        self.assertEqual(mic.get_incident(other_incident)["status"], "OPEN")

    def test_missing_target_explains_usage(self):
        update, message = self._update()
        context = _FakeContext(status="administrator", args=[])
        self._run(self.app.cmd_member(update, context))
        self.assertIn("ใช้งาน", "\n".join(message.replies))

    def test_unknown_username_target_is_explained_not_silently_empty(self):
        update, message = self._update()
        context = _FakeContext(status="administrator", args=["@nobody_here"])
        self._run(self.app.cmd_member(update, context))
        joined = "\n".join(message.replies)
        self.assertIn("ไม่พบบัญชี", joined)
        self.assertIn("ไม่ใช่ 'ไม่มีบัญชีนี้'", joined)

    def test_report_generation_is_itself_audited(self):
        self._member()
        update, message = self._update()
        context = _FakeContext(status="administrator", args=[str(USER)])
        self._run(self.app.cmd_member(update, context))
        actions = [a["action"] for a in mic.list_admin_actions(CHAT)]
        self.assertIn("REPORT_GENERATED", actions)

    def test_purge_without_subcommand_only_shows_settings(self):
        self._member()
        mi.add_timeline_event(CHAT, USER, mi.TimelineEvent.JOINED, now=T0)
        update, message = self._update()
        context = _FakeContext(status="administrator", args=[])
        self._run(self.app.cmd_memberpurge(update, context))
        self.assertIn("การเก็บรักษาข้อมูลสมาชิก", "\n".join(message.replies))
        self.assertIsNotNone(mi.get_member(CHAT, USER))  # nothing deleted

    def test_export_is_sent_as_a_document(self):
        self._member()
        update, message = self._update()
        context = _FakeContext(status="administrator", args=[str(USER), "json"])
        self._run(self.app.cmd_memberreport(update, context))
        self.assertTrue(any(r.startswith("DOC:") for r in message.replies))


if __name__ == "__main__":
    unittest.main()
