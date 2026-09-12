"""
test_member_intel.py — Phase 9 test suite (identity / timeline / risk / patterns).

Same isolation pattern as test_findings.py: each test gets a fresh,
isolated SQLite file (tempfile), so tests never share state and can run
in any order. Exercises member_intel.py through its real public API
(record_observation / observe_membership_change / add_timeline_event /
assess_risk / find_correlated_activity / purge_expired / forget_member)
rather than poking at its tables -- that is the surface app.py calls.

Deliberate negative coverage, because the most important property of
this module is that it never invents history:
  - an omitted username must not be recorded as "username removed"
  - a membership event with no invite link must report UNAVAILABLE, not
    "no invite link used"
  - an unknown timeline event type must be rejected, not stored
  - an account the bot never saw must read as "not observed", not "clean"
"""

import os
import json
import sqlite3
import tempfile
import unittest

import security
import member_intel as mi

T0 = 1_700_000_000  # fixed clock: every test passes now= explicitly
CHAT_FIXTURE = -100


class MemberIntelTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        mi.DB_PATH = path
        security.security_db_init()
        mi.member_intel_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers ----

    def _seen(self, chat_id=-100, user_id=555, username="alpha", display="Alpha",
              now=T0, counts_as_message=True, message_id=1):
        return mi.record_observation(chat_id, user_id, username=username,
                                     display_name=display, counts_as_message=counts_as_message,
                                     message_id=message_id, now=now)


# ---------------- Phase 16: database initialization ----------------

class DatabaseInitTests(MemberIntelTestCase):
    def test_init_creates_every_table_and_index(self):
        conn = sqlite3.connect(self._db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_mi_%'")}
        conn.close()
        for expected in ("mi_members", "mi_identity_history", "mi_timeline",
                         "mi_join_events", "mi_risk_snapshots", "mi_message_patterns"):
            self.assertIn(expected, tables)
        self.assertTrue(indexes, "expected idx_mi_* indexes to exist")

    def test_repeated_initialization_is_idempotent(self):
        for _ in range(3):
            mi.member_intel_db_init()
        self._seen()
        self.assertIsNotNone(mi.get_member(-100, 555))

    def test_existing_rows_survive_reinitialization(self):
        self._seen()
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0)
        mi.member_intel_db_init()  # simulate a process restart re-running init
        self.assertIsNotNone(mi.get_member(-100, 555))
        self.assertEqual(len(mi.get_timeline(-100, 555)), 2)  # FIRST_MESSAGE + JOINED

    def test_init_does_not_touch_security_tables(self):
        security.record_event(-100, 555, security.SecurityEvent.SPAM, "x")
        mi.member_intel_db_init()
        self.assertEqual(security.get_risk_score(-100, 555), 15)


# ---------------- Phase 1: member identity registry ----------------

class MemberRegistryTests(MemberIntelTestCase):
    def test_member_created_on_first_observation(self):
        result = self._seen()
        self.assertTrue(result.created)
        self.assertTrue(result.first_message)
        member = mi.get_member(-100, 555)
        self.assertEqual(member["user_id"], 555)
        self.assertEqual(member["username"], "alpha")
        self.assertEqual(member["display_name"], "Alpha")
        self.assertEqual(member["first_seen_at"], T0)
        self.assertEqual(member["observed_message_count"], 1)
        self.assertEqual(member["membership_status"], mi.MembershipStatus.UNKNOWN.value)

    def test_member_ref_is_stable_and_scoped_to_chat(self):
        a = self._seen(chat_id=-100, user_id=555)
        b = mi.record_observation(-100, 555, username="alpha", now=T0 + 5)
        self.assertEqual(a.member_ref, b.member_ref)
        other = mi.record_observation(-200, 555, username="alpha", now=T0)
        self.assertNotEqual(a.member_ref, other.member_ref)

    def test_repeated_observations_accumulate_not_duplicate(self):
        for i in range(5):
            self._seen(now=T0 + i, message_id=i)
        member = mi.get_member(-100, 555)
        self.assertEqual(member["observed_message_count"], 5)
        self.assertEqual(member["first_message_at"], T0)
        self.assertEqual(member["last_message_at"], T0 + 4)
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute("SELECT COUNT(*) FROM mi_members").fetchone()[0]
        conn.close()
        self.assertEqual(rows, 1)

    def test_user_id_is_the_identity_not_the_username(self):
        """A freed username reused by another account must not merge the
        two identities: user_id stays the key, and the two lookups answer
        two different questions."""
        self._seen(user_id=1, username="shared")
        mi.record_observation(-100, 1, username=None, now=T0 + 10)
        # a second account later takes the freed username
        mi.record_observation(-100, 2, username="shared", display_name="B", now=T0 + 20)

        # "who holds it now" -> only account 2
        current = mi.find_members_by_username("shared")
        self.assertEqual([m["user_id"] for m in current], [2])
        # "who was observed CHANGING away from it" -> only account 1, since
        # account 2 was first seen already holding it (no change observed)
        holders = {h["user_id"] for h in mi.find_historic_username_holders("shared")}
        self.assertEqual(holders, {1})
        # the two accounts remain separate records
        self.assertNotEqual(mi.get_member(-100, 1)["member_ref"],
                            mi.get_member(-100, 2)["member_ref"])

    def test_unknown_member_reads_as_not_observed(self):
        profile = mi.get_member_profile(-100, 999)
        self.assertFalse(profile["known"])
        self.assertIsNone(profile["member"])
        self.assertEqual(profile["identity_timeline"]["current_username"], mi.UNAVAILABLE)

    def test_username_lookup_of_unknown_handle_is_empty_not_error(self):
        self.assertEqual(mi.find_members_by_username("nobody"), [])
        self.assertEqual(mi.find_members_by_username(""), [])
        self.assertEqual(mi.find_members_by_username("@"), [])

    def test_long_and_blank_values_are_capped_not_rejected(self):
        mi.record_observation(-100, 3, username="x" * 500, display_name=" " * 10, now=T0)
        member = mi.get_member(-100, 3)
        self.assertEqual(len(member["username"]), mi.MAX_USERNAME_LEN)
        self.assertIsNone(member["display_name"])  # blank is not an observed name

    def test_at_prefix_is_normalized_away(self):
        mi.record_observation(-100, 4, username="@handle", now=T0)
        self.assertEqual(mi.get_member(-100, 4)["username"], "handle")


# ---------------- Phase 2: identity history ----------------

class IdentityHistoryTests(MemberIntelTestCase):
    def test_username_change_is_recorded(self):
        self._seen(username="alpha", now=T0)
        result = mi.record_observation(-100, 555, username="beta", display_name="Alpha",
                                       now=T0 + 100)
        self.assertTrue(result.username_changed)
        self.assertEqual(result.previous_username, "alpha")
        history = mi.get_identity_history(-100, 555)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["field"], "username")
        self.assertEqual((history[0]["old_value"], history[0]["new_value"]),
                         ("alpha", "beta"))

    def test_display_name_change_is_recorded(self):
        self._seen(display="Alpha", now=T0)
        result = mi.record_observation(-100, 555, username="alpha", display_name="Alpha2",
                                       now=T0 + 100)
        self.assertTrue(result.display_name_changed)
        fields = [h["field"] for h in mi.get_identity_history(-100, 555)]
        self.assertEqual(fields, ["display_name"])

    def test_explicit_none_username_records_a_removal(self):
        self._seen(username="alpha", now=T0)
        result = mi.record_observation(-100, 555, username=None, display_name="Alpha",
                                       now=T0 + 100)
        self.assertTrue(result.username_changed)
        history = mi.get_identity_history(-100, 555)
        self.assertIsNone(history[0]["new_value"])
        self.assertIsNone(mi.get_member(-100, 555)["username"])

    def test_omitted_username_is_not_a_removal(self):
        """The core anti-fabrication property: a caller that simply does
        not supply a username must never produce a 'username removed'
        record, and must not blank the stored handle."""
        self._seen(username="alpha", now=T0)
        result = mi.record_observation(-100, 555, display_name="Alpha", now=T0 + 100)
        self.assertFalse(result.username_changed)
        self.assertEqual(mi.get_member(-100, 555)["username"], "alpha")
        self.assertEqual(mi.get_identity_history(-100, 555), [])

    def test_omitted_display_name_does_not_erase_or_rename(self):
        self._seen(display="Alpha", now=T0)
        result = mi.record_observation(-100, 555, username="alpha", now=T0 + 100)
        self.assertFalse(result.display_name_changed)
        self.assertEqual(mi.get_member(-100, 555)["display_name"], "Alpha")

    def test_account_that_never_had_a_username_stays_silent(self):
        mi.record_observation(-100, 6, username=None, display_name="NoHandle", now=T0)
        mi.record_observation(-100, 6, username=None, display_name="NoHandle", now=T0 + 10)
        self.assertEqual(mi.get_identity_history(-100, 6), [])

    def test_unchanged_values_produce_no_history(self):
        for i in range(4):
            self._seen(now=T0 + i, message_id=i)
        self.assertEqual(mi.get_identity_history(-100, 555), [])

    def test_identity_timeline_is_oldest_first_with_unknown_before(self):
        self._seen(username="alpha", now=T0)
        mi.record_observation(-100, 555, username="beta", display_name="Alpha", now=T0 + 100)
        mi.record_observation(-100, 555, username=None, display_name="Alpha", now=T0 + 200)
        mi.record_observation(-100, 555, username="gamma", display_name="Alpha", now=T0 + 300)
        timeline = mi.build_identity_timeline(-100, 555)
        self.assertEqual(timeline["unknown_before"], T0)
        self.assertEqual([e["observed_at"] for e in timeline["entries"]],
                         [T0 + 100, T0 + 200, T0 + 300])
        self.assertEqual(timeline["entries"][1]["to"], mi.UNAVAILABLE)
        self.assertEqual(timeline["current_username"], "gamma")

    def test_identity_change_emits_a_timeline_event(self):
        self._seen(username="alpha", now=T0)
        mi.record_observation(-100, 555, username="beta", display_name="Alpha", now=T0 + 100)
        types = [e["event_type"] for e in mi.get_timeline(-100, 555)]
        self.assertIn(mi.TimelineEvent.IDENTITY_CHANGED.value, types)


# ---------------- Phase 3: activity timeline ----------------

class TimelineTests(MemberIntelTestCase):
    def test_first_message_recorded_once(self):
        self._seen(now=T0, message_id=1)
        self._seen(now=T0 + 10, message_id=2)
        first = [e for e in mi.get_timeline(-100, 555)
                 if e["event_type"] == mi.TimelineEvent.FIRST_MESSAGE.value]
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["message_id"], 1)

    def test_event_metadata_is_round_tripped(self):
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.WARNING_ISSUED,
                              actor_user_id=777, message_id=42, incident_id=9,
                              detail="2/3", meta={"rule": "spam"}, now=T0)
        event = mi.get_timeline(-100, 555)[0]
        self.assertEqual(event["actor_user_id"], 777)
        self.assertEqual(event["message_id"], 42)
        self.assertEqual(event["incident_id"], 9)
        self.assertEqual(event["detail"], "2/3")
        self.assertEqual(event["meta"]["rule"], "spam")

    def test_unknown_event_type_is_rejected(self):
        self.assertIsNone(mi.add_timeline_event(-100, 555, "TOTALLY_MADE_UP"))
        self.assertEqual(mi.get_timeline(-100, 555), [])

    def test_actor_defaults_to_none_not_a_guess(self):
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.MESSAGE_REMOVED, now=T0)
        self.assertIsNone(mi.get_timeline(-100, 555)[0]["actor_user_id"])

    def test_timeline_is_newest_first_and_filterable(self):
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0)
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.WARNING_ISSUED, now=T0 + 10)
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.BANNED, now=T0 + 20)
        events = mi.get_timeline(-100, 555)
        self.assertEqual([e["event_type"] for e in events],
                         ["BANNED", "WARNING_ISSUED", "JOINED"])
        filtered = mi.get_timeline(-100, 555, event_types=["BANNED"])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(mi.get_timeline(-100, 555, since=T0 + 15)[0]["event_type"], "BANNED")

    def test_event_type_filter_rejects_unknown_values(self):
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0)
        self.assertEqual(mi.get_timeline(-100, 555, event_types=["DROP TABLE"]), [])

    def test_chat_timeline_spans_members(self):
        mi.add_timeline_event(-100, 1, mi.TimelineEvent.JOINED, now=T0)
        mi.add_timeline_event(-100, 2, mi.TimelineEvent.JOINED, now=T0 + 5)
        mi.add_timeline_event(-200, 3, mi.TimelineEvent.JOINED, now=T0 + 6)
        events = mi.get_chat_timeline(-100)
        self.assertEqual({e["user_id"] for e in events}, {1, 2})

    def test_read_limit_is_clamped(self):
        for i in range(30):
            mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0 + i)
        self.assertEqual(len(mi.get_timeline(-100, 555)), mi.DEFAULT_PAGE_LIMIT)
        self.assertEqual(len(mi.get_timeline(-100, 555, limit=99999)), 30)
        self.assertEqual(len(mi.get_timeline(-100, 555, limit=-5)), mi.DEFAULT_PAGE_LIMIT)
        self.assertEqual(len(mi.get_timeline(-100, 555, limit="junk")),
                         mi.DEFAULT_PAGE_LIMIT)


# ---------------- Phase 4: entry & invite tracking ----------------

class JoinAndInviteTests(MemberIntelTestCase):
    def test_join_recorded_with_invite_attribution(self):
        mi.observe_membership_change(-100, 555, "left", "member", username="alpha",
                                     display_name="Alpha",
                                     invite_link="https://t.me/+abc",
                                     invite_link_name="promo",
                                     invite_link_creator_id=777, now=T0)
        rows = mi.get_join_history(-100, 555)
        self.assertEqual(rows[0]["kind"], mi.JoinKind.JOINED.value)
        self.assertEqual(rows[0]["invite_link"], "https://t.me/+abc")
        self.assertEqual(rows[0]["invite_link_creator_id"], 777)
        member = mi.get_member(-100, 555)
        self.assertEqual(member["membership_status"], "MEMBER")
        self.assertEqual(member["join_count"], 1)

    def test_join_without_invite_reports_unavailable_not_absent(self):
        mi.observe_membership_change(-100, 555, "left", "member", username="alpha", now=T0)
        row = mi.get_join_history(-100, 555)[0]
        self.assertIsNone(row["invite_link"])
        self.assertEqual(row["invite_attribution"], mi.UNAVAILABLE)
        stats = mi.get_invite_link_stats(-100)
        self.assertEqual(stats["joins_without_attribution"], 1)
        self.assertEqual(stats["links"], [])
        self.assertIn("ไม่ได้หมายความว่า", stats["note"])

    def test_leave_then_join_is_a_rejoin(self):
        mi.observe_membership_change(-100, 555, "left", "member", username="a", now=T0)
        mi.observe_membership_change(-100, 555, "member", "left", username="a", now=T0 + 10)
        mi.observe_membership_change(-100, 555, "left", "member", username="a", now=T0 + 20)
        kinds = [r["kind"] for r in mi.get_join_history(-100, 555)]
        self.assertEqual(kinds, ["REJOINED", "LEFT", "JOINED"])
        member = mi.get_member(-100, 555)
        self.assertEqual((member["join_count"], member["leave_count"]), (2, 1))

    def test_first_ever_join_is_not_a_rejoin(self):
        mi.observe_membership_change(-100, 555, None, "member", username="a", now=T0)
        self.assertEqual(mi.get_join_history(-100, 555)[0]["kind"], "JOINED")

    def test_kicked_maps_to_banned_and_emits_timeline_event(self):
        mi.observe_membership_change(-100, 555, "member", "kicked", username="a",
                                     actor_user_id=777, now=T0)
        self.assertEqual(mi.get_member(-100, 555)["membership_status"], "BANNED")
        banned = [e for e in mi.get_timeline(-100, 555)
                  if e["event_type"] == mi.TimelineEvent.BANNED.value]
        self.assertEqual(len(banned), 1)
        self.assertEqual(banned[0]["actor_user_id"], 777)

    def test_ban_does_not_also_emit_a_plain_left(self):
        """A ban is a departure, but recording it as LEFT too would let a
        reader conclude the account left voluntarily."""
        mi.observe_membership_change(CHAT_FIXTURE, 555, "left", "member", now=T0)
        mi.observe_membership_change(CHAT_FIXTURE, 555, "member", "kicked",
                                     actor_user_id=777, now=T0 + 10)
        types = [e["event_type"] for e in mi.get_timeline(CHAT_FIXTURE, 555)]
        self.assertIn("BANNED", types)
        self.assertEqual(types.count("LEFT"), 0)
        # the join_events row still records the transition itself
        self.assertEqual(mi.get_join_history(CHAT_FIXTURE, 555)[0]["new_status"], "BANNED")

    def test_plain_unban_to_left_is_still_recorded(self):
        """Telegram sends BANNED -> LEFT for an ordinary unban. Dropping
        that would leave a ban with no visible end in the timeline."""
        mi.observe_membership_change(CHAT_FIXTURE, 555, "member", "kicked",
                                     actor_user_id=777, now=T0)
        mi.observe_membership_change(CHAT_FIXTURE, 555, "kicked", "left",
                                     actor_user_id=777, now=T0 + 10)
        types = [e["event_type"] for e in mi.get_timeline(CHAT_FIXTURE, 555)]
        self.assertIn("UNBANNED", types)

    def test_unban_and_rejoin_is_recorded(self):
        mi.observe_membership_change(CHAT_FIXTURE, 555, "member", "kicked", now=T0)
        mi.observe_membership_change(CHAT_FIXTURE, 555, "kicked", "member", now=T0 + 10)
        types = [e["event_type"] for e in mi.get_timeline(CHAT_FIXTURE, 555)]
        self.assertIn("UNBANNED", types)

    def test_restriction_and_release_emit_events(self):
        mi.observe_membership_change(-100, 555, "member", "restricted", username="a", now=T0)
        mi.observe_membership_change(-100, 555, "restricted", "member", username="a",
                                     now=T0 + 10)
        types = {e["event_type"] for e in mi.get_timeline(-100, 555)}
        self.assertIn("RESTRICTED", types)
        self.assertIn("UNRESTRICTED", types)

    def test_promotion_and_demotion_are_observed(self):
        mi.observe_membership_change(-100, 555, "member", "administrator", now=T0)
        mi.observe_membership_change(-100, 555, "administrator", "member", now=T0 + 10)
        types = {e["event_type"] for e in mi.get_timeline(-100, 555)}
        self.assertIn("PROMOTED", types)
        self.assertIn("DEMOTED", types)

    def test_unknown_status_string_is_normalized_not_stored_raw(self):
        mi.observe_membership_change(-100, 555, "member", "weird_new_status", now=T0)
        self.assertEqual(mi.get_member(-100, 555)["membership_status"], "UNKNOWN")

    def test_invite_link_stats_group_and_count(self):
        for i, user in enumerate((1, 2, 3)):
            mi.observe_membership_change(-100, user, "left", "member",
                                         invite_link="https://t.me/+same",
                                         invite_link_creator_id=777, now=T0 + i)
        mi.observe_membership_change(-100, 4, "left", "member", now=T0 + 10)
        stats = mi.get_invite_link_stats(-100)
        self.assertEqual(stats["total_observed_joins"], 4)
        self.assertEqual(stats["joins_without_attribution"], 1)
        self.assertEqual(len(stats["links"]), 1)
        self.assertEqual(stats["links"][0]["joins"], 3)

    def test_status_change_without_presence_change_records_no_join_row(self):
        mi.observe_membership_change(-100, 555, "member", "administrator", now=T0)
        self.assertEqual(mi.get_join_history(-100, 555), [])


# ---------------- Phase 5: explainable risk engine ----------------

class RiskEngineTests(MemberIntelTestCase):
    def test_no_events_is_zero_and_low(self):
        assessment = mi.assess_risk(-100, 555, now=T0)
        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.level, "LOW")
        self.assertEqual(assessment.reasons, [])

    def test_score_is_itemised_and_explainable(self):
        security.record_event(-100, 555, security.SecurityEvent.BLOCKED_LINK, "x")
        security.record_event(-100, 555, security.SecurityEvent.SPAM, "y")
        assessment = mi.assess_risk(-100, 555)
        codes = {r.code: r for r in assessment.reasons}
        self.assertIn("BLOCKED_LINK", codes)
        self.assertIn("SPAM", codes)
        self.assertEqual(assessment.score, sum(r.points for r in assessment.reasons))
        for reason in assessment.reasons:
            self.assertTrue(reason.label)
            self.assertEqual(reason.points, min(reason.weight * reason.count,
                                                mi.RISK_SIGNALS[reason.code].cap))

    def test_per_signal_cap_is_enforced(self):
        for _ in range(50):
            security.record_event(-100, 555, security.SecurityEvent.MESSAGE_DELETED, "x")
        assessment = mi.assess_risk(-100, 555)
        deleted = next(r for r in assessment.reasons if r.code == "MESSAGE_DELETED")
        self.assertEqual(deleted.points, mi.RISK_SIGNALS["MESSAGE_DELETED"].cap)

    def test_score_is_clamped_to_100(self):
        for event in (security.SecurityEvent.SPAM, security.SecurityEvent.BLOCKED_LINK,
                      security.SecurityEvent.MUTE, security.SecurityEvent.MENTION_SPAM,
                      security.SecurityEvent.WARNING, security.SecurityEvent.AI_FLAGGED_SPAM):
            for _ in range(20):
                security.record_event(-100, 555, event, "x")
        assessment = mi.assess_risk(-100, 555)
        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.level, "HIGH")

    def test_events_outside_the_window_do_not_count(self):
        security.record_event(-100, 555, security.SecurityEvent.MUTE, "old")
        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE security_events SET created_at = created_at - ?",
                     (mi.RISK_WINDOW_SECONDS + 3600,))
        conn.commit()
        conn.close()
        self.assertEqual(mi.assess_risk(-100, 555).score, 0)

    def test_levels_follow_configured_thresholds(self):
        self.assertEqual(mi.risk_level(mi.RISK_MEDIUM_MIN - 1), "LOW")
        self.assertEqual(mi.risk_level(mi.RISK_MEDIUM_MIN), "MEDIUM")
        self.assertEqual(mi.risk_level(mi.RISK_HIGH_MIN), "HIGH")

    def test_cumulative_security_score_is_reported_separately(self):
        security.record_event(-100, 555, security.SecurityEvent.MUTE, "x")
        assessment = mi.assess_risk(-100, 555)
        self.assertEqual(assessment.cumulative_risk_score, 25)
        self.assertEqual(assessment.cumulative_event_count, 1)
        self.assertNotEqual(assessment.score, assessment.cumulative_risk_score)

    def test_risk_engine_never_writes_to_user_behavior(self):
        security.record_event(-100, 555, security.SecurityEvent.SPAM, "x")
        before = security.get_behavior(-100, 555)
        mi.assess_risk(-100, 555, persist=True)
        self.assertEqual(security.get_behavior(-100, 555), before)

    def test_assessment_carries_the_disclaimer(self):
        self.assertIn("ไม่ใช่ข้อพิสูจน์", mi.assess_risk(-100, 555).as_dict()["disclaimer"])

    def test_duplicate_messages_are_a_signal(self):
        for i in range(3):
            mi.record_message_pattern(-100, 555, "buy now buy now", message_id=i, now=T0 + i)
        codes = {r.code for r in mi.assess_risk(-100, 555, now=T0 + 10).reasons}
        self.assertIn("DUPLICATE_MESSAGE", codes)

    def test_timeline_outcomes_are_signals(self):
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.BANNED, now=T0)
        codes = {r.code for r in mi.assess_risk(-100, 555, now=T0 + 10).reasons}
        self.assertIn("BANNED", codes)

    def test_snapshot_persists_reasons(self):
        security.record_event(-100, 555, security.SecurityEvent.SPAM, "x")
        mi.assess_risk(-100, 555, persist=True)
        snapshots = mi.get_risk_snapshots(-100, 555)
        self.assertEqual(len(snapshots), 1)
        self.assertTrue(snapshots[0]["reasons"])
        self.assertEqual(snapshots[0]["level"], snapshots[0]["level"].upper())

    def test_no_snapshot_unless_requested(self):
        security.record_event(-100, 555, security.SecurityEvent.SPAM, "x")
        mi.assess_risk(-100, 555)
        self.assertEqual(mi.get_risk_snapshots(-100, 555), [])

    def test_unweighted_event_type_contributes_nothing(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("INSERT INTO security_events (chat_id, user_id, event_type, detail, "
                     "created_at) VALUES (?, ?, ?, ?, ?)",
                     (-100, 555, "SOME_FUTURE_EVENT", "x", T0))
        conn.commit()
        conn.close()
        self.assertEqual(mi.assess_risk(-100, 555, now=T0 + 5).score, 0)

    def test_missing_incident_table_does_not_break_scoring(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("DROP TABLE IF EXISTS mi_incidents")
        conn.commit()
        conn.close()
        security.record_event(-100, 555, security.SecurityEvent.SPAM, "x")
        self.assertGreater(mi.assess_risk(-100, 555).score, 0)

    def test_top_risk_members_is_sorted_and_bounded(self):
        security.record_event(-100, 1, security.SecurityEvent.MESSAGE_DELETED, "x")
        for _ in range(3):
            security.record_event(-100, 2, security.SecurityEvent.MUTE, "x")
        top = mi.top_risk_members(-100, limit=5)
        self.assertEqual(top[0].user_id, 2)
        self.assertGreaterEqual(top[0].score, top[1].score)

    def test_top_risk_excludes_other_chats(self):
        security.record_event(-200, 9, security.SecurityEvent.MUTE, "x")
        self.assertEqual(mi.top_risk_members(-100), [])

    def test_zero_window_falls_back_to_default(self):
        self.assertEqual(mi.assess_risk(-100, 555, window_seconds=0).window_seconds,
                         mi.RISK_WINDOW_SECONDS)


# ---------------- Phase 11: pattern analysis ----------------

class PatternAnalysisTests(MemberIntelTestCase):
    def test_identical_message_across_accounts_is_flagged_as_review(self):
        for user in (1, 2, 3):
            mi.record_message_pattern(-100, user, "Join my channel now!", now=T0)
        data = mi.find_correlated_activity(-100, window_seconds=3600, min_accounts=3,
                                           now=T0 + 60)
        self.assertEqual(len(data["identical_messages"]), 1)
        item = data["identical_messages"][0]
        self.assertEqual(item["account_count"], 3)
        self.assertEqual(set(item["user_ids"]), {1, 2, 3})
        self.assertEqual(item["verdict"], "REQUIRES_REVIEW")

    def test_output_never_claims_same_person(self):
        for user in (1, 2, 3):
            mi.record_message_pattern(-100, user, "same text", now=T0)
        data = mi.find_correlated_activity(-100, min_accounts=3, now=T0 + 60)
        blob = json.dumps(data, ensure_ascii=False)
        for forbidden in ("same person", "คนเดียวกัน คือ", "SAME_PERSON", "IS_ALT"):
            self.assertNotIn(forbidden, blob)
        self.assertIn("ไม่ใช่ข้อพิสูจน์", data["disclaimer"])
        for item in data["identical_messages"]:
            self.assertEqual(item["verdict"], "REQUIRES_REVIEW")

    def test_shared_url_host_is_flagged(self):
        for user in (1, 2, 3):
            mi.record_message_pattern(-100, user,
                                      f"check https://bad.example/{user} out", now=T0)
        data = mi.find_correlated_activity(-100, min_accounts=3, now=T0 + 60)
        self.assertEqual(len(data["shared_url_hosts"]), 1)
        self.assertEqual(data["shared_url_hosts"][0]["url_host"], "bad.example")

    def test_below_threshold_is_not_flagged(self):
        for user in (1, 2):
            mi.record_message_pattern(-100, user, "same text", now=T0)
        data = mi.find_correlated_activity(-100, min_accounts=3, now=T0 + 60)
        self.assertEqual(data["identical_messages"], [])

    def test_one_account_repeating_itself_is_not_a_cross_account_pattern(self):
        for i in range(5):
            mi.record_message_pattern(-100, 1, "same text", message_id=i, now=T0 + i)
        data = mi.find_correlated_activity(-100, min_accounts=2, now=T0 + 60)
        self.assertEqual(data["identical_messages"], [])

    def test_outside_window_is_not_correlated(self):
        for user in (1, 2, 3):
            mi.record_message_pattern(-100, user, "same text", now=T0)
        data = mi.find_correlated_activity(-100, window_seconds=60, min_accounts=3,
                                           now=T0 + 100000)
        self.assertEqual(data["identical_messages"], [])

    def test_min_accounts_never_drops_below_two(self):
        mi.record_message_pattern(-100, 1, "solo", now=T0)
        data = mi.find_correlated_activity(-100, min_accounts=1, now=T0 + 10)
        self.assertEqual(data["min_accounts"], 2)
        self.assertEqual(data["identical_messages"], [])

    def test_fingerprint_is_stored_not_text(self):
        mi.record_message_pattern(-100, 1, "secret words here", now=T0)
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute("SELECT text_hash FROM mi_message_patterns").fetchall()
        conn.close()
        self.assertEqual(len(rows[0][0]), 64)
        self.assertNotIn("secret", rows[0][0])

    def test_fingerprint_ignores_case_and_whitespace(self):
        mi.record_message_pattern(-100, 1, "Buy   NOW", now=T0)
        mi.record_message_pattern(-100, 2, "buy now", now=T0)
        data = mi.find_correlated_activity(-100, min_accounts=2, now=T0 + 10)
        self.assertEqual(len(data["identical_messages"]), 1)

    def test_empty_text_is_not_recorded(self):
        mi.record_message_pattern(-100, 1, "", now=T0)
        mi.record_message_pattern(-100, 1, "   ", now=T0)
        conn = sqlite3.connect(self._db_path)
        count = conn.execute("SELECT COUNT(*) FROM mi_message_patterns").fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)


# ---------------- Phase 14: retention / purge ----------------

class RetentionTests(MemberIntelTestCase):
    def tearDown(self):
        mi.RETENTION_TIMELINE_DAYS = 0
        mi.RETENTION_IDENTITY_DAYS = 0
        mi.RETENTION_JOIN_DAYS = 0
        mi.RETENTION_RISK_SNAPSHOT_DAYS = 90
        super().tearDown()

    def test_zero_retention_keeps_everything(self):
        mi.RETENTION_TIMELINE_DAYS = 0
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0 - 10 * 86400)
        deleted = mi.purge_expired(chat_id=-100, now=T0)
        self.assertEqual(deleted.get("mi_timeline", 0), 0)
        self.assertEqual(len(mi.get_timeline(-100, 555)), 1)

    def test_configured_retention_deletes_only_old_rows(self):
        mi.RETENTION_TIMELINE_DAYS = 7
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0 - 30 * 86400)
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.LEFT, now=T0 - 1 * 86400)
        deleted = mi.purge_expired(chat_id=-100, now=T0)
        self.assertEqual(deleted["mi_timeline"], 1)
        remaining = [e["event_type"] for e in mi.get_timeline(-100, 555)]
        self.assertEqual(remaining, ["LEFT"])

    def test_purge_is_scoped_to_one_chat_when_asked(self):
        mi.RETENTION_TIMELINE_DAYS = 7
        mi.add_timeline_event(-100, 1, mi.TimelineEvent.JOINED, now=T0 - 30 * 86400)
        mi.add_timeline_event(-200, 2, mi.TimelineEvent.JOINED, now=T0 - 30 * 86400)
        mi.purge_expired(chat_id=-100, now=T0)
        self.assertEqual(len(mi.get_timeline(-100, 1)), 0)
        self.assertEqual(len(mi.get_timeline(-200, 2)), 1)

    def test_purge_writes_an_audit_entry(self):
        mi.RETENTION_TIMELINE_DAYS = 7
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0 - 30 * 86400)
        mi.purge_expired(chat_id=-100, actor_user_id=777, now=T0)
        actions = [r["action"] for r in security.get_recent_audit_log(-100, limit=10)]
        self.assertIn("MEMBER_DATA_PURGED", actions)

    def test_retention_settings_are_reported(self):
        settings = mi.retention_settings()
        for key in ("timeline_days", "identity_days", "join_days",
                    "risk_snapshot_days", "store_message_content"):
            self.assertIn(key, settings)

    def test_forget_member_removes_this_modules_rows_only(self):
        self._seen(now=T0)
        mi.observe_membership_change(-100, 555, "left", "member", username="alpha", now=T0)
        mi.record_message_pattern(-100, 555, "hello", now=T0)
        mi.assess_risk(-100, 555, persist=True)
        security.record_event(-100, 555, security.SecurityEvent.SPAM, "x")

        deleted = mi.forget_member(-100, 555, actor_user_id=777, now=T0)
        self.assertGreater(sum(deleted.values()), 0)
        self.assertIsNone(mi.get_member(-100, 555))
        self.assertEqual(mi.get_timeline(-100, 555), [])
        self.assertEqual(mi.get_identity_history(-100, 555), [])
        self.assertEqual(mi.get_join_history(-100, 555), [])
        # security.py's own records are deliberately untouched
        self.assertEqual(security.get_risk_score(-100, 555), 15)

    def test_forget_member_leaves_other_members_alone(self):
        self._seen(user_id=1, now=T0)
        self._seen(user_id=2, now=T0)
        mi.forget_member(-100, 1, actor_user_id=777, now=T0)
        self.assertIsNone(mi.get_member(-100, 1))
        self.assertIsNotNone(mi.get_member(-100, 2))

    def test_forget_unknown_member_is_a_noop_not_an_error(self):
        deleted = mi.forget_member(-100, 424242, actor_user_id=777, now=T0)
        self.assertEqual(sum(deleted.values()), 0)

    def test_forget_writes_an_audit_entry(self):
        self._seen(now=T0)
        mi.forget_member(-100, 555, actor_user_id=777, now=T0)
        actions = [r["action"] for r in security.get_recent_audit_log(-100, limit=10)]
        self.assertIn("MEMBER_RECORD_FORGOTTEN", actions)


# ---------------- Malformed / hostile input ----------------

class MalformedInputTests(MemberIntelTestCase):
    def test_unserialisable_meta_is_coerced_not_raised(self):
        """json.dumps(default=str) coerces an unexpected value to text
        rather than raising. The event is still recorded -- an
        observation must not be lost because its metadata was odd."""
        event_id = mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED,
                                         meta={"obj": object()}, now=T0)
        self.assertIsNotNone(event_id)
        self.assertIsInstance(mi.get_timeline(-100, 555)[0]["meta"]["obj"], str)

    def test_sql_looking_text_is_stored_as_data(self):
        payload = "Robert'); DROP TABLE mi_members;--"
        mi.record_observation(-100, 555, username=payload, display_name=payload, now=T0)
        member = mi.get_member(-100, 555)
        self.assertTrue(member["display_name"].startswith("Robert'"))
        conn = sqlite3.connect(self._db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertIn("mi_members", tables)

    def test_username_lookup_with_sql_payload_returns_nothing(self):
        self._seen(now=T0)
        self.assertEqual(mi.find_members_by_username("' OR 1=1 --"), [])

    def test_detail_and_meta_are_length_capped(self):
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED,
                              detail="x" * 5000,
                              meta={"k": "y" * 10000}, now=T0)
        event = mi.get_timeline(-100, 555)[0]
        self.assertLessEqual(len(event["detail"]), mi.MAX_DETAIL_LEN)

    def test_corrupt_meta_json_reads_as_empty(self):
        mi.add_timeline_event(-100, 555, mi.TimelineEvent.JOINED, now=T0)
        conn = sqlite3.connect(self._db_path)
        conn.execute("UPDATE mi_timeline SET meta_json='{not json'")
        conn.commit()
        conn.close()
        self.assertEqual(mi.get_timeline(-100, 555)[0]["meta"], {})

    def test_string_ids_are_coerced(self):
        mi.record_observation("-100", "555", username="alpha", now=T0)
        self.assertIsNotNone(mi.get_member(-100, 555))

    def test_custody_style_missing_filters_return_empty(self):
        self.assertEqual(mi.find_historic_username_holders(""), [])


if __name__ == "__main__":
    unittest.main()
