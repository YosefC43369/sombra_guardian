"""
test_debt_ledger.py — test suite for debt_ledger.py (the "เซ็นสินค้า"
deterministic data layer).

Same isolation pattern as test_bb_report.py / test_scope_policy.py /
test_findings.py: each test gets a fresh, isolated SQLite tempfile
(security.DB_PATH and debt_ledger.DB_PATH both repointed at it in
setUp), so tests never touch the real bot.db and never see another
test's rows.
"""

import os
import re
import tempfile
import unittest
from datetime import date
from decimal import Decimal

import security
import debt_ledger as dl
import debt_report as dr


class DebtLedgerTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        dl.DB_PATH = path
        security.security_db_init()
        dl.debt_ledger_db_init()
        
    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass
            
    # ---- helpers ----
    
    def _sign(self, name="สมชาย", amount="50", desc="น้ำท่อม", chat_id=1,
              recorded_by=999, entry_date=None):
        satang = dl.parse_amount_to_satang(amount)
        return dl.add_entry(chat_id, name, satang, recorded_by,
                             item_description=desc, entry_date=entry_date)
                            
    # ---- parse_amount_to_satang ----

    def test_parse_amount_plain_integer(self):
        self.assertEqual(dl.parse_amount_to_satang("50"), 5000)

    def test_parse_amount_decimal(self):
        self.assertEqual(dl.parse_amount_to_satang("12.50"), 1250)

    def test_parse_amount_with_thousands_separator(self):
        self.assertEqual(dl.parse_amount_to_satang("1,050"), 105000)

    def test_parse_amount_rejects_zero(self):
        self.assertIsNone(dl.parse_amount_to_satang("0"))

    def test_parse_amount_rejects_negative(self):
        self.assertIsNone(dl.parse_amount_to_satang("-50"))

    def test_parse_amount_rejects_non_numeric(self):
        self.assertIsNone(dl.parse_amount_to_satang("ห้าสิบ"))

    def test_parse_amount_rejects_empty_and_none(self):
        self.assertIsNone(dl.parse_amount_to_satang(""))
        self.assertIsNone(dl.parse_amount_to_satang(None))

    def test_parse_amount_rejects_absurdly_large(self):
        self.assertIsNone(dl.parse_amount_to_satang("99999999"))

    def test_parse_amount_rejects_overlong_raw_string(self):
        self.assertIsNone(dl.parse_amount_to_satang("1" * 40))

    # ---- format_baht ----

    def test_format_baht_whole_number(self):
        self.assertEqual(dl.format_baht(5000), "50 บาท")

    def test_format_baht_with_decimals(self):
        self.assertEqual(dl.format_baht(1250), "12.50 บาท")

    def test_format_baht_thousands_separator(self):
        self.assertEqual(dl.format_baht(105000), "1,050 บาท")

    # ---- add_entry / validation ----

    def test_add_entry_success(self):
        result = self._sign()
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.entry_id)

    def test_add_entry_empty_name_rejected(self):
        result = self._sign(name="   ")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NAME_REQUIRED")

    def test_add_entry_name_too_long_rejected(self):
        result = self._sign(name="ก" * (dl.MAX_NAME_LEN + 1))
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NAME_TOO_LONG")

    def test_add_entry_invalid_amount_rejected(self):
        result = dl.add_entry(1, "สมชาย", -100, recorded_by=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_AMOUNT")

    def test_add_entry_zero_amount_rejected(self):
        result = dl.add_entry(1, "สมชาย", 0, recorded_by=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_AMOUNT")

    def test_add_entry_description_too_long_rejected(self):
        result = self._sign(desc="ก" * (dl.MAX_DESCRIPTION_LEN + 1))
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "DESCRIPTION_TOO_LONG")

    def test_add_entry_defaults_to_unpaid(self):
        result = self._sign()
        entry = dl.get_entry(result.entry_id)
        self.assertEqual(entry["status"], dl.EntryStatus.UNPAID.value)

    def test_add_entry_defaults_to_today_bangkok(self):
        result = self._sign()
        entry = dl.get_entry(result.entry_id)
        self.assertEqual(entry["entry_date"], dl.today_bangkok_date())

    def test_add_entry_writes_audit_log(self):
        result = self._sign(chat_id=42, recorded_by=7)
        self.assertTrue(result.ok)
        log = security.get_recent_audit_log(42, limit=5)
        self.assertTrue(any(row["action"] == "DEBT_SIGNED" for row in log))

    def test_add_entry_db_error_returns_reason(self):
        # Simulate a DB-layer failure (e.g. table dropped/unreachable)
        # without touching the validation path above it.
        import sqlite3
        real_connect = sqlite3.connect
        def _boom(*a, **kw):
            raise sqlite3.Error("simulated failure")
        sqlite3.connect = _boom
        try:
            result = self._sign()
        finally:
            sqlite3.connect = real_connect
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "DB_ERROR")

    # ---- list_entries ----
    
    def test_list_entries_filters_by_chat(self):
        self._sign(chat_id=1)
        self._sign(chat_id=2)
        self.assertEqual(len(dl.list_entries(1)), 1)
        self.assertEqual(len(dl.list_entries(2)), 1)

    def test_list_entries_filters_by_status(self):
        r1 = self._sign()
        self._sign()
        dl.mark_entry_paid(r1.entry_id, actor_user_id=999)
        unpaid = dl.list_entries(1, status=dl.EntryStatus.UNPAID.value)
        paid = dl.list_entries(1, status=dl.EntryStatus.PAID.value)
        self.assertEqual(len(unpaid), 1)
        self.assertEqual(len(paid), 1)

    def test_list_entries_debtor_name_case_insensitive(self):
        self._sign(name="Somchai")
        rows = dl.list_entries(1, debtor_name="somchai")
        self.assertEqual(len(rows), 1)

    def test_list_entries_ordered_oldest_first(self):
        self._sign(entry_date="2026-08-01")
        self._sign(entry_date="2026-08-15")
        rows = dl.list_entries(1)
        self.assertEqual(rows[0]["entry_date"], "2026-08-01")
        self.assertEqual(rows[1]["entry_date"], "2026-08-15")

    # ---- mark_entry_paid ----

    def test_mark_entry_paid_success(self):
        r = self._sign()
        result = dl.mark_entry_paid(r.entry_id, actor_user_id=999)
        self.assertTrue(result.ok)
        self.assertEqual(result.updated_count, 1)
        entry = dl.get_entry(r.entry_id)
        self.assertEqual(entry["status"], dl.EntryStatus.PAID.value)
        self.assertIsNotNone(entry["paid_at"])
        self.assertEqual(entry["paid_by"], 999)

    def test_mark_entry_paid_already_paid_rejected(self):
        r = self._sign()
        dl.mark_entry_paid(r.entry_id, actor_user_id=999)
        result = dl.mark_entry_paid(r.entry_id, actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ALREADY_PAID")

    def test_mark_entry_paid_not_found(self):
        result = dl.mark_entry_paid(999999, actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ENTRY_NOT_FOUND")

    def test_mark_entry_paid_wrong_chat_not_found(self):
        r = self._sign(chat_id=1)
        result = dl.mark_entry_paid(r.entry_id, actor_user_id=999, chat_id=2)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ENTRY_NOT_FOUND")

    def test_mark_entry_paid_writes_audit_log(self):
        r = self._sign(chat_id=5)
        dl.mark_entry_paid(r.entry_id, actor_user_id=999, chat_id=5)
        log = security.get_recent_audit_log(5, limit=5)
        self.assertTrue(any(row["action"] == "DEBT_PAID" for row in log))

    # ---- mark_debtor_paid ----

    def test_mark_debtor_paid_bulk(self):
        self._sign(name="สมชาย", amount="50")
        self._sign(name="สมชาย", amount="30")
        self._sign(name="วิชัย", amount="20")
        result = dl.mark_debtor_paid(1, "สมชาย", actor_user_id=999)
        self.assertTrue(result.ok)
        self.assertEqual(result.updated_count, 2)
        self.assertEqual(result.total_satang, 8000)
        # the other debtor's entry must remain untouched
        remaining = dl.list_entries(1, status=dl.EntryStatus.UNPAID.value)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["debtor_name"], "วิชัย")

    def test_mark_debtor_paid_no_unpaid_entries(self):
        result = dl.mark_debtor_paid(1, "ไม่มีตัวตน", actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NO_UNPAID_ENTRIES")

    def test_mark_debtor_paid_empty_name_rejected(self):
        result = dl.mark_debtor_paid(1, "   ", actor_user_id=999)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NAME_REQUIRED")

    def test_mark_debtor_paid_respects_date_range(self):
        self._sign(name="สมชาย", amount="50", entry_date="2026-07-15")
        self._sign(name="สมชาย", amount="30", entry_date="2026-08-15")
        result = dl.mark_debtor_paid(
            1, "สมชาย", actor_user_id=999,
            date_from="2026-08-01", date_to="2026-08-31",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.updated_count, 1)
        self.assertEqual(result.total_satang, 3000)
        # July entry must still be unpaid
        remaining = dl.list_entries(1, status=dl.EntryStatus.UNPAID.value)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["entry_date"], "2026-07-15")

    def test_mark_debtor_paid_writes_bulk_audit_log(self):
        self._sign(name="สมชาย", amount="50", chat_id=3)
        dl.mark_debtor_paid(3, "สมชาย", actor_user_id=999)
        log = security.get_recent_audit_log(3, limit=5)
        self.assertTrue(any(row["action"] == "DEBT_PAID_BULK" for row in log))

    # ---- summarize_by_debtor ----

    def test_summarize_multiple_debtors(self):
        self._sign(name="สมชาย", amount="50", entry_date="2026-08-05")
        self._sign(name="สมชาย", amount="100", entry_date="2026-08-10")
        self._sign(name="สมชาย", amount="50", entry_date="2026-08-12")
        self._sign(name="สมชาย", amount="100", entry_date="2026-08-14")
        self._sign(name="สมชาย", amount="50", entry_date="2026-08-16")
        self._sign(name="วิชัย", amount="60", entry_date="2026-08-06")
        self._sign(name="วิชัย", amount="60", entry_date="2026-08-08")
        self._sign(name="วิชัย", amount="60", entry_date="2026-08-20")
        date_from, date_to = dl.month_range(2026, 8)
        summary = dl.summarize_by_debtor(1, date_from, date_to)
        self.assertEqual(summary["grand_total_count"], 8)
        self.assertEqual(summary["grand_total_satang"], 53000)
        names = [d["debtor_name"] for d in summary["by_debtor"]]
        self.assertEqual(names, sorted(names))  # sorted by name
        somchai = next(d for d in summary["by_debtor"] if d["debtor_name"] == "สมชาย")
        self.assertEqual(somchai["count"], 5)
        self.assertEqual(somchai["total_satang"], 35000)

    def test_summarize_excludes_paid_entries_from_unpaid_totals(self):
        r1 = self._sign(name="สมชาย", amount="50", entry_date="2026-08-05")
        self._sign(name="สมชาย", amount="30", entry_date="2026-08-06")
        dl.mark_entry_paid(r1.entry_id, actor_user_id=999)
        date_from, date_to = dl.month_range(2026, 8)
        summary = dl.summarize_by_debtor(1, date_from, date_to)  # default status=unpaid
        self.assertEqual(summary["grand_total_count"], 1)
        self.assertEqual(summary["grand_total_satang"], 3000)

    def test_summarize_empty_month_returns_zeroed_totals(self):
        date_from, date_to = dl.month_range(2026, 3)
        summary = dl.summarize_by_debtor(1, date_from, date_to)
        self.assertEqual(summary["by_debtor"], [])
        self.assertEqual(summary["grand_total_satang"], 0)
        self.assertEqual(summary["grand_total_count"], 0)

    def test_summarize_single_debtor_multiple_entries(self):
        self._sign(name="สมชาย", amount="10", entry_date="2026-05-01")
        self._sign(name="สมชาย", amount="20", entry_date="2026-05-15")
        self._sign(name="สมชาย", amount="30", entry_date="2026-05-31")
        date_from, date_to = dl.month_range(2026, 5)
        summary = dl.summarize_by_debtor(1, date_from, date_to)
        self.assertEqual(len(summary["by_debtor"]), 1)
        self.assertEqual(summary["by_debtor"][0]["count"], 3)
        self.assertEqual(summary["by_debtor"][0]["total_satang"], 6000)
        
    def test_repeated_sign_same_name_accumulates_total(self):
        self._sign(name="สมชาย", amount="50")
        self._sign(name="สมชาย", amount="50")
        self._sign(name="สมชาย", amount="30")
        summary = dl.summarize_debtors(1)
        somchai = next(d for d in summary["by_debtor"] if d["debtor_name"] == "สมชาย")
        self.assertEqual(somchai["total_satang"], 13000)  # 130 บาท

    def test_repeated_sign_same_name_keeps_every_transaction_row(self):
        self._sign(name="สมชาย", amount="50")
        self._sign(name="สมชาย", amount="50")
        self._sign(name="สมชาย", amount="30")
        rows = dl.list_entries(1, debtor_name="สมชาย")
        self.assertEqual(len(rows), 3)
        self.assertEqual([r["amount_satang"] for r in rows], [5000, 5000, 3000])

    def test_summarize_debtors_multiple_people_grand_total(self):
        self._sign(name="สมชาย", amount="130")
        self._sign(name="สมหญิง", amount="80")
        self._sign(name="John", amount="50")
        summary = dl.summarize_debtors(1)
        self.assertEqual(len(summary["by_debtor"]), 3)
        self.assertEqual(summary["grand_total_satang"], 26000)  # 260 บาท

    def test_summarize_debtors_ignores_date(self):
        self._sign(name="สมชาย", amount="50", entry_date="2020-01-01")
        self._sign(name="สมชาย", amount="30", entry_date="2026-08-19")
        summary = dl.summarize_debtors(1)
        self.assertEqual(summary["grand_total_satang"], 8000)

    def test_summarize_debtors_paid_reduces_unpaid_total(self):
        r1 = self._sign(name="สมชาย", amount="50")
        self._sign(name="สมชาย", amount="30")
        dl.mark_entry_paid(r1.entry_id, actor_user_id=999)
        summary = dl.summarize_debtors(1)
        somchai = next(d for d in summary["by_debtor"] if d["debtor_name"] == "สมชาย")
        self.assertEqual(somchai["total_satang"], 3000)

    def test_summarize_debtors_fully_paid_debtor_excluded_from_unpaid(self):
        r1 = self._sign(name="สมชาย", amount="50")
        dl.mark_entry_paid(r1.entry_id, actor_user_id=999)
        summary = dl.summarize_debtors(1)
        names = [d["debtor_name"] for d in summary["by_debtor"]]
        self.assertNotIn("สมชาย", names)

    def test_summarize_debtors_reflects_new_sign_after_refresh(self):
        self._sign(name="สมชาย", amount="50")
        before = dl.summarize_debtors(1)["grand_total_satang"]
        self._sign(name="สมชาย", amount="50")
        after = dl.summarize_debtors(1)["grand_total_satang"]
        self.assertEqual(before, 5000)
        self.assertEqual(after, 10000)

    # ---- debtor_ref / resolve_debtor_ref (Requirement #4/#5/#6/#7) ----

    def test_debtor_ref_is_short_and_callback_safe(self):
        ref = dl.debtor_ref(1, "สมชาย" * 20)
        self.assertLessEqual(len(f"debt:user:{ref}".encode("utf-8")), 64)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{10}", ref))

    def test_debtor_ref_stable_and_resolves_back_to_name(self):
        self._sign(name="สมชาย", amount="50")
        ref = dl.debtor_ref(1, "สมชาย")
        self.assertEqual(dl.debtor_ref(1, "สมชาย"), ref)
        self.assertEqual(dl.resolve_debtor_ref(1, ref), "สมชาย")

    def test_debtor_ref_scoped_by_chat_id(self):
        self._sign(name="สมชาย", amount="50", chat_id=1)
        self._sign(name="สมชาย", amount="50", chat_id=2)
        ref_chat1 = dl.debtor_ref(1, "สมชาย")
        self.assertIsNone(dl.resolve_debtor_ref(2, ref_chat1))

    def test_resolve_debtor_ref_unknown_returns_none_not_crash(self):
        self._sign(name="สมชาย", amount="50")
        self.assertIsNone(dl.resolve_debtor_ref(1, "0000000000"))

    # ---- pagination stays within Telegram message limits (Requirement #14) ----

    def test_format_debtor_detail_paginates_long_history(self):
        for i in range(25):
            self._sign(name="สมชาย", amount="10", entry_date="2026-08-01")
        entries = dl.list_entries(1, debtor_name="สมชาย", limit=dl.SUMMARY_ROW_LIMIT)
        text = dr.format_debtor_detail("สมชาย", 25000, entries, expanded=True,
                                        page=1, page_size=10)
        self.assertEqual(text.count("•"), 10)
        self.assertIn("หน้า 1/3", text)

    def test_format_debtor_detail_collapsed_has_no_transaction_lines(self):
        self._sign(name="สมชาย", amount="50")
        entries = dl.list_entries(1, debtor_name="สมชาย")
        text = dr.format_debtor_detail("สมชาย", 5000, entries, expanded=False)
        self.assertNotIn("•", text)
        self.assertIn("สมชาย", text)

    # ---- month_range / previous_month_range / parse_month_arg (boundaries) ----

    def test_month_range_regular_month(self):
        self.assertEqual(dl.month_range(2026, 8), ("2026-08-01", "2026-08-31"))

    def test_month_range_first_day(self):
        first, _ = dl.month_range(2026, 8)
        self.assertEqual(first, "2026-08-01")

    def test_month_range_last_day_30_day_month(self):
        _, last = dl.month_range(2026, 4)
        self.assertEqual(last, "2026-04-30")

    def test_month_range_last_day_31_day_month(self):
        _, last = dl.month_range(2026, 8)
        self.assertEqual(last, "2026-08-31")

    def test_month_range_february_non_leap_year(self):
        _, last = dl.month_range(2026, 2)
        self.assertEqual(last, "2026-02-28")

    def test_month_range_february_leap_year(self):
        _, last = dl.month_range(2024, 2)
        self.assertEqual(last, "2024-02-29")

    def test_month_range_december_year_rollover(self):
        first, last = dl.month_range(2026, 12)
        self.assertEqual((first, last), ("2026-12-01", "2026-12-31"))

    def test_month_range_invalid_month_raises(self):
        with self.assertRaises(ValueError):
            dl.month_range(2026, 13)

    def test_previous_month_range_regular(self):
        result = dl.previous_month_range(today=date(2026, 8, 15))
        self.assertEqual(result, ("2026-07-01", "2026-07-31"))

    def test_previous_month_range_january_rolls_back_to_previous_december(self):
        result = dl.previous_month_range(today=date(2026, 1, 10))
        self.assertEqual(result, ("2025-12-01", "2025-12-31"))

    def test_previous_month_range_first_of_month(self):
        # Even on the 1st, "previous month" must be the prior full month,
        # not the current (just-started) one.
        result = dl.previous_month_range(today=date(2026, 3, 1))
        self.assertEqual(result, ("2026-02-01", "2026-02-28"))

    def test_parse_month_arg_valid(self):
        self.assertEqual(dl.parse_month_arg("2026-08"), ("2026-08-01", "2026-08-31"))

    def test_parse_month_arg_invalid_shape(self):
        self.assertIsNone(dl.parse_month_arg("Aug 2026"))

    def test_parse_month_arg_invalid_month_number(self):
        self.assertIsNone(dl.parse_month_arg("2026-13"))

    def test_parse_month_arg_empty(self):
        self.assertIsNone(dl.parse_month_arg(""))
        self.assertIsNone(dl.parse_month_arg(None))


class DebtReportTestCase(unittest.TestCase):
    """format_* functions in debt_report.py are pure string formatting
    over data debt_ledger.py already computed -- these tests exercise
    that formatting layer against real dl.add_entry/summarize_by_debtor
    output, same fixture pattern as DebtLedgerTestCase above."""

    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        dl.DB_PATH = path
        security.security_db_init()
        dl.debt_ledger_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    def _sign(self, name="สมชาย", amount="50", desc="ข้าวกล่อง", chat_id=1,
              recorded_by=999, entry_date=None):
        satang = dl.parse_amount_to_satang(amount)
        return dl.add_entry(chat_id, name, satang, recorded_by,
                             item_description=desc, entry_date=entry_date)

    def test_format_sign_confirmation_contains_key_fields(self):
        r = self._sign(name="สมชาย", amount="50", desc="ข้าวกล่อง")
        entry = dl.get_entry(r.entry_id)
        text = dr.format_sign_confirmation(entry)
        self.assertIn("สมชาย", text)
        self.assertIn("50 บาท", text)
        self.assertIn("น้ำท่อม", text)
        self.assertIn(f"#{r.entry_id}", text)
        self.assertIn("ยังไม่ชำระ", text)

    def test_format_sign_confirmation_omits_missing_description(self):
        # "เลขที่รายการ:" (entry-number label) legitimately contains the
        # substring "รายการ:", so check for the item-description line
        # specifically (its own line, not a substring of another label).
        r = self._sign(desc="")
        entry = dl.get_entry(r.entry_id)
        text = dr.format_sign_confirmation(entry)
        self.assertNotIn("\nรายการ:", text)

    def test_format_entries_table_empty(self):
        text = dr.format_entries_table([])
        self.assertIn("ไม่มีรายการ", text)

    def test_format_entries_table_includes_all_rows(self):
        self._sign(name="สมชาย", amount="50")
        self._sign(name="วิชัย", amount="20")
        entries = dl.list_entries(1)
        text = dr.format_entries_table(entries)
        self.assertIn("สมชาย", text)
        self.assertIn("วิชัย", text)
        self.assertIn("วันที่ | ชื่อ | รายการ | จำนวนเงิน | สถานะ", text)

    def test_format_debt_summary_empty_range(self):
        date_from, date_to = dl.month_range(2026, 3)
        summary = dl.summarize_by_debtor(1, date_from, date_to)
        text = dr.format_debt_summary(summary)
        self.assertIn("ไม่มีรายการในช่วงเวลานี้", text)

    def test_format_debt_summary_includes_grand_total(self):
        self._sign(name="สมชาย", amount="50", entry_date="2026-08-01")
        self._sign(name="วิชัย", amount="30", entry_date="2026-08-02")
        date_from, date_to = dl.month_range(2026, 8)
        summary = dl.summarize_by_debtor(1, date_from, date_to)
        text = dr.format_debt_summary(summary)
        self.assertIn("สมชาย", text)
        self.assertIn("วิชัย", text)
        self.assertIn("รวมทั้งหมด", text)
        self.assertIn("80 บาท", text)  # grand total

    def test_format_paid_single(self):
        text = dr.format_paid_single(7, 5000)
        self.assertIn("#7", text)
        self.assertIn("50 บาท", text)

    def test_format_paid_bulk_with_range(self):
        text = dr.format_paid_bulk("สมชาย", 3, 8000, "2026-08-01", "2026-08-31")
        self.assertIn("สมชาย", text)
        self.assertIn("3 รายการ", text)
        self.assertIn("80 บาท", text)
        self.assertIn("01/08/2026", text)


if __name__ == "__main__":
    unittest.main()