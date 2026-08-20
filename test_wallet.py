"""
test_wallet.py — Unit test suite for wallet.py (Wallet / Payment /
Transaction Ledger data layer), plus its one deliberate integration
point with debt_ledger.py (pay_debt_with_wallet).

Same isolation pattern as test_scope_policy.py / test_findings.py:
every test gets a fresh tempfile SQLite DB, security.DB_PATH / wt.DB_PATH
/ dl.DB_PATH are all repointed at it (each module captured its own copy
of DB_PATH via `from security import DB_PATH`, so all three must be set
individually — same reason test_scope_policy.py sets both security.DB_PATH
and sp.DB_PATH), and tests exercise wallet.py's real public API rather
than poking at internal tables directly.

Covers: wallet creation/balance, amount parsing, deposit request/confirm/
reject, withdrawal request/approve/reject/cancel (incl. the immediate-hold
double-spend guard), transfer (incl. self-transfer, insufficient balance,
idempotency replay), payment requests/"bills" (create/pay/cancel, self-
payment block, targeted-payer enforcement, expiry), admin manual
adjustment (credit/debit, reason required), transaction history
pagination, admin all-transactions view, chat-scoping isolation,
recompute_balance audit consistency, the debt_ledger.py integration
(atomic success AND atomic failure -- insufficient balance must leave
the debt entry untouched), and a real concurrency/race-condition test
(threaded withdrawals against a shared balance) proving the negative-
balance guard actually holds under contention, not just in isolation.
"""

import os
import tempfile
import threading
import unittest

import security
import debt_ledger as dl
import wallet as wt


class WalletTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        wt.DB_PATH = path
        dl.DB_PATH = path
        security.security_db_init()
        wt.wallet_db_init()
        dl.debt_ledger_db_init()

    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass

    # ---- fixture helpers ----

    CHAT = 1
    ADMIN = 999

    def _balance(self, user_id, chat_id=CHAT):
        return wt.get_wallet(chat_id, user_id)["balance_satang"]

    def _fund(self, user_id, satang, chat_id=CHAT, admin_id=ADMIN):
        """Shortcut to get money into a wallet for test setup, via the
        real deposit-request + admin-confirm flow (never pokes the
        table directly)."""
        req = wt.request_deposit(chat_id, user_id, satang)
        self.assertTrue(req.ok)
        result = wt.confirm_deposit(chat_id, req.data["transaction"]["transaction_id"], admin_id)
        self.assertTrue(result.ok)

    # ==================== Wallet / balance ====================

    def test_wallet_created_lazily_with_zero_balance(self):
        row = wt.get_wallet(self.CHAT, 111)
        self.assertEqual(row["balance_satang"], 0)
        self.assertEqual(row["chat_id"], self.CHAT)
        self.assertEqual(row["user_id"], 111)

    def test_chat_scoping_isolates_wallets(self):
        self._fund(111, 5000, chat_id=1)
        self.assertEqual(self._balance(111, chat_id=1), 5000)
        self.assertEqual(self._balance(111, chat_id=2), 0)

    # ==================== Amount parsing ====================

    def test_parse_amount_to_satang_valid(self):
        self.assertEqual(wt.parse_amount_to_satang("10"), 1000)
        self.assertEqual(wt.parse_amount_to_satang("10.5"), 1050)
        self.assertEqual(wt.parse_amount_to_satang("1,000"), 100000)
        self.assertEqual(wt.parse_amount_to_satang("0.01"), 1)

    def test_parse_amount_to_satang_rejects_invalid(self):
        for bad in (None, "", "0", "-5", "abc", "1e999", "999999999999999999999999999999999999",
                    "NaN", "inf"):
            self.assertIsNone(wt.parse_amount_to_satang(bad), msg=f"should reject {bad!r}")

    def test_parse_amount_to_satang_caps_max(self):
        self.assertIsNone(wt.parse_amount_to_satang("1000001"))
        self.assertIsNotNone(wt.parse_amount_to_satang("1000000"))

    def test_parse_signed_amount_to_satang(self):
        self.assertEqual(wt.parse_signed_amount_to_satang("50"), 5000)
        self.assertEqual(wt.parse_signed_amount_to_satang("-50"), -5000)
        self.assertIsNone(wt.parse_signed_amount_to_satang("-0"))
        self.assertIsNone(wt.parse_signed_amount_to_satang("abc"))

    def test_format_baht_whole_and_fractional(self):
        self.assertEqual(wt.format_baht(150000), "1,500 บาท")
        self.assertEqual(wt.format_baht(150050), "1,500.50 บาท")

    # ==================== Deposits ====================

    def test_deposit_request_is_pending_not_credited(self):
        req = wt.request_deposit(self.CHAT, 111, 1000)
        self.assertTrue(req.ok)
        self.assertEqual(self._balance(111), 0)  # not credited yet

    def test_deposit_confirm_credits_balance(self):
        req = wt.request_deposit(self.CHAT, 111, 1000)
        result = wt.confirm_deposit(self.CHAT, req.data["transaction"]["transaction_id"], self.ADMIN)
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 1000)

    def test_deposit_confirm_twice_fails(self):
        req = wt.request_deposit(self.CHAT, 111, 1000)
        tx_id = req.data["transaction"]["transaction_id"]
        self.assertTrue(wt.confirm_deposit(self.CHAT, tx_id, self.ADMIN).ok)
        second = wt.confirm_deposit(self.CHAT, tx_id, self.ADMIN)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PROCESSED")
        self.assertEqual(self._balance(111), 1000)  # not double-credited

    def test_deposit_reject_never_credits(self):
        req = wt.request_deposit(self.CHAT, 111, 1000)
        tx_id = req.data["transaction"]["transaction_id"]
        result = wt.reject_deposit(self.CHAT, tx_id, self.ADMIN, reason="ไม่พบสลิป")
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 0)
        # rejected deposit can't later be confirmed
        self.assertFalse(wt.confirm_deposit(self.CHAT, tx_id, self.ADMIN).ok)

    def test_deposit_confirm_wrong_chat_not_found(self):
        req = wt.request_deposit(self.CHAT, 111, 1000)
        tx_id = req.data["transaction"]["transaction_id"]
        result = wt.confirm_deposit(999, tx_id, self.ADMIN)  # wrong chat
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "NOT_FOUND")

    def test_deposit_invalid_amount_rejected(self):
        self.assertFalse(wt.request_deposit(self.CHAT, 111, 0).ok)
        self.assertFalse(wt.request_deposit(self.CHAT, 111, -100).ok)
        self.assertFalse(wt.request_deposit(self.CHAT, 111, None).ok)

    def test_list_pending_deposits(self):
        wt.request_deposit(self.CHAT, 111, 1000)
        wt.request_deposit(self.CHAT, 222, 2000)
        pending = wt.list_pending_deposits(self.CHAT)
        self.assertEqual(len(pending), 2)

    # ==================== Withdrawals ====================

    def test_withdrawal_request_holds_funds_immediately(self):
        self._fund(111, 1000)
        result = wt.request_withdrawal(self.CHAT, 111, 400)
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 600)  # held immediately, not on approval

    def test_withdrawal_request_insufficient_balance(self):
        self._fund(111, 100)
        result = wt.request_withdrawal(self.CHAT, 111, 200)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(self._balance(111), 100)  # untouched

    def test_withdrawal_double_request_hold_prevents_double_spend(self):
        """Requirement #3: requesting the same money twice while the
        first request is still pending must fail on the second call,
        because request_withdrawal() debits (holds) immediately."""
        self._fund(111, 500)
        first = wt.request_withdrawal(self.CHAT, 111, 400)
        self.assertTrue(first.ok)
        second = wt.request_withdrawal(self.CHAT, 111, 400)  # only 100 left
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "INSUFFICIENT_BALANCE")

    def test_withdrawal_approve_finalizes_without_changing_balance(self):
        self._fund(111, 1000)
        req = wt.request_withdrawal(self.CHAT, 111, 400)
        request_id = req.data["request_id"]
        result = wt.approve_withdrawal(self.CHAT, request_id, self.ADMIN)
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 600)  # already held, unchanged by approval

    def test_withdrawal_reject_refunds_held_amount(self):
        self._fund(111, 1000)
        req = wt.request_withdrawal(self.CHAT, 111, 400)
        request_id = req.data["request_id"]
        result = wt.reject_withdrawal(self.CHAT, request_id, self.ADMIN, reason="ข้อมูลไม่ครบ")
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 1000)  # refunded

    def test_withdrawal_cancel_by_owner_refunds(self):
        self._fund(111, 1000)
        req = wt.request_withdrawal(self.CHAT, 111, 400)
        request_id = req.data["request_id"]
        result = wt.cancel_withdrawal(self.CHAT, request_id, 111)
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 1000)

    def test_withdrawal_cancel_by_non_owner_forbidden(self):
        self._fund(111, 1000)
        req = wt.request_withdrawal(self.CHAT, 111, 400)
        request_id = req.data["request_id"]
        result = wt.cancel_withdrawal(self.CHAT, request_id, 222)  # not the owner
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FORBIDDEN")
        self.assertEqual(self._balance(111), 600)  # still held, not refunded

    def test_withdrawal_approve_already_processed_fails(self):
        self._fund(111, 1000)
        req = wt.request_withdrawal(self.CHAT, 111, 400)
        request_id = req.data["request_id"]
        wt.approve_withdrawal(self.CHAT, request_id, self.ADMIN)
        second = wt.approve_withdrawal(self.CHAT, request_id, self.ADMIN)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PROCESSED")

    # ==================== Transfers ====================

    def test_transfer_moves_balance_both_legs(self):
        self._fund(111, 1000)
        result = wt.transfer(self.CHAT, 111, 222, 300, note="ค่าข้าว")
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 700)
        self.assertEqual(self._balance(222), 300)

    def test_transfer_insufficient_balance(self):
        self._fund(111, 100)
        result = wt.transfer(self.CHAT, 111, 222, 200)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(self._balance(111), 100)
        self.assertEqual(self._balance(222), 0)

    def test_transfer_self_not_allowed(self):
        self._fund(111, 1000)
        result = wt.transfer(self.CHAT, 111, 111, 100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SELF_TRANSFER_NOT_ALLOWED")
        self.assertEqual(self._balance(111), 1000)

    def test_transfer_invalid_amount(self):
        self._fund(111, 1000)
        for bad in (0, -50, None):
            result = wt.transfer(self.CHAT, 111, 222, bad)
            self.assertFalse(result.ok)
            self.assertEqual(result.reason, "INVALID_AMOUNT")

    def test_transfer_idempotency_key_replay_is_safe(self):
        """A duplicate-delivered Telegram update (or a double-tapped
        confirm) must not move money twice."""
        self._fund(111, 1000)
        key = "update-12345"
        first = wt.transfer(self.CHAT, 111, 222, 300, idempotency_key=key)
        self.assertTrue(first.ok)
        second = wt.transfer(self.CHAT, 111, 222, 300, idempotency_key=key)
        self.assertTrue(second.ok)
        self.assertTrue(second.data.get("already_processed"))
        # balance only moved once
        self.assertEqual(self._balance(111), 700)
        self.assertEqual(self._balance(222), 300)

    # ==================== Payment requests / "bills" ====================

    def test_payment_request_create_and_pay(self):
        result = wt.create_payment_request(self.CHAT, 111, 500, description="ค่าอาหารเที่ยง")
        self.assertTrue(result.ok)
        payment_id = result.data["payment_id"]
        self._fund(222, 1000)
        pay_result = wt.pay_payment_request(self.CHAT, payment_id, 222)
        self.assertTrue(pay_result.ok)
        self.assertEqual(self._balance(222), 500)
        self.assertEqual(self._balance(111), 500)
        req = wt.get_payment_request(self.CHAT, payment_id)
        self.assertEqual(req["status"], wt.PaymentStatus.PAID.value)

    def test_payment_request_self_payment_not_allowed(self):
        result = wt.create_payment_request(self.CHAT, 111, 500, payer_user_id=111)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SELF_PAYMENT_NOT_ALLOWED")

    def test_payment_request_targeted_payer_enforced(self):
        result = wt.create_payment_request(self.CHAT, 111, 500, payer_user_id=222)
        payment_id = result.data["payment_id"]
        self._fund(333, 1000)  # a different member tries to pay someone else's bill
        pay_result = wt.pay_payment_request(self.CHAT, payment_id, 333)
        self.assertFalse(pay_result.ok)
        self.assertEqual(pay_result.reason, "FORBIDDEN")

    def test_payment_request_open_bill_payable_by_anyone(self):
        result = wt.create_payment_request(self.CHAT, 111, 500)  # no payer_user_id
        payment_id = result.data["payment_id"]
        self._fund(333, 1000)
        pay_result = wt.pay_payment_request(self.CHAT, payment_id, 333)
        self.assertTrue(pay_result.ok)

    def test_payment_request_pay_twice_fails(self):
        result = wt.create_payment_request(self.CHAT, 111, 500)
        payment_id = result.data["payment_id"]
        self._fund(222, 1000)
        self._fund(333, 1000)
        self.assertTrue(wt.pay_payment_request(self.CHAT, payment_id, 222).ok)
        second = wt.pay_payment_request(self.CHAT, payment_id, 333)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PROCESSED")

    def test_payment_request_insufficient_balance_leaves_bill_pending(self):
        result = wt.create_payment_request(self.CHAT, 111, 500)
        payment_id = result.data["payment_id"]
        self._fund(222, 100)  # not enough
        pay_result = wt.pay_payment_request(self.CHAT, payment_id, 222)
        self.assertFalse(pay_result.ok)
        self.assertEqual(pay_result.reason, "INSUFFICIENT_BALANCE")
        req = wt.get_payment_request(self.CHAT, payment_id)
        self.assertEqual(req["status"], wt.PaymentStatus.PENDING.value)
        self.assertEqual(self._balance(222), 100)  # untouched

    def test_payment_request_cancel_by_creator(self):
        result = wt.create_payment_request(self.CHAT, 111, 500)
        payment_id = result.data["payment_id"]
        cancel = wt.cancel_payment_request(self.CHAT, payment_id, 111)
        self.assertTrue(cancel.ok)
        req = wt.get_payment_request(self.CHAT, payment_id)
        self.assertEqual(req["status"], wt.PaymentStatus.CANCELLED.value)

    def test_payment_request_cancel_by_non_creator_forbidden(self):
        result = wt.create_payment_request(self.CHAT, 111, 500)
        payment_id = result.data["payment_id"]
        cancel = wt.cancel_payment_request(self.CHAT, payment_id, 222, is_admin_actor=False)
        self.assertFalse(cancel.ok)
        self.assertEqual(cancel.reason, "FORBIDDEN")

    def test_payment_request_cancel_by_admin_allowed(self):
        result = wt.create_payment_request(self.CHAT, 111, 500)
        payment_id = result.data["payment_id"]
        cancel = wt.cancel_payment_request(self.CHAT, payment_id, self.ADMIN, is_admin_actor=True)
        self.assertTrue(cancel.ok)

    def test_payment_request_expiry(self):
        result = wt.create_payment_request(self.CHAT, 111, 500, expires_in_seconds=-1)
        payment_id = result.data["payment_id"]
        req = wt.get_payment_request(self.CHAT, payment_id)  # lazy view-time expiry
        self.assertEqual(req["status"], wt.PaymentStatus.EXPIRED.value)
        self._fund(222, 1000)
        pay_result = wt.pay_payment_request(self.CHAT, payment_id, 222)
        self.assertFalse(pay_result.ok)
        self.assertEqual(pay_result.reason, "EXPIRED")

    def test_list_payment_requests_by_role(self):
        wt.create_payment_request(self.CHAT, 111, 500, payer_user_id=222)
        wt.create_payment_request(self.CHAT, 111, 300)  # open bill
        as_payer = wt.list_payment_requests(self.CHAT, 222, role="payer")
        self.assertEqual(len(as_payer), 2)  # targeted-at-me + open bill
        as_requester = wt.list_payment_requests(self.CHAT, 111, role="requester")
        self.assertEqual(len(as_requester), 2)

    # ==================== Admin manual adjustment ====================

    def test_admin_adjust_credit(self):
        result = wt.admin_adjust(self.CHAT, 111, 1000, self.ADMIN, reason="โบนัส")
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 1000)

    def test_admin_adjust_debit(self):
        self._fund(111, 1000)
        result = wt.admin_adjust(self.CHAT, 111, -400, self.ADMIN, reason="แก้ไขยอดผิดพลาด")
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 600)

    def test_admin_adjust_debit_insufficient_balance(self):
        self._fund(111, 100)
        result = wt.admin_adjust(self.CHAT, 111, -400, self.ADMIN, reason="แก้ไขยอดผิดพลาด")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(self._balance(111), 100)

    def test_admin_adjust_requires_reason(self):
        result = wt.admin_adjust(self.CHAT, 111, 500, self.ADMIN, reason="")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "REASON_REQUIRED")
        result2 = wt.admin_adjust(self.CHAT, 111, 500, self.ADMIN, reason="   ")
        self.assertFalse(result2.ok)
        self.assertEqual(result2.reason, "REASON_REQUIRED")

    def test_admin_adjust_zero_amount_invalid(self):
        result = wt.admin_adjust(self.CHAT, 111, 0, self.ADMIN, reason="เหตุผล")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_AMOUNT")

    # ==================== History / admin views ====================

    def test_history_pagination(self):
        self._fund(111, 100000)
        for _ in range(15):
            wt.transfer(self.CHAT, 111, 222, 100)
        page1 = wt.list_transactions(self.CHAT, 111, page=1, page_size=10)
        self.assertEqual(len(page1["items"]), 10)
        self.assertEqual(page1["total_count"], 16)  # 1 deposit + 15 transfers-out
        self.assertEqual(page1["total_pages"], 2)
        page2 = wt.list_transactions(self.CHAT, 111, page=2, page_size=10)
        self.assertEqual(len(page2["items"]), 6)

    def test_list_all_transactions_admin_filter_by_user(self):
        self._fund(111, 1000)
        self._fund(222, 1000)
        page_data = wt.list_all_transactions_admin(self.CHAT, user_id=111)
        self.assertTrue(all(t["user_id"] == 111 for t in page_data["items"]))
        self.assertEqual(page_data["total_count"], 1)

    def test_recompute_balance_matches_ledger_after_mixed_activity(self):
        self._fund(111, 10000)
        wt.transfer(self.CHAT, 111, 222, 2000)
        wt.admin_adjust(self.CHAT, 111, 500, self.ADMIN, reason="โบนัส")
        wt.admin_adjust(self.CHAT, 222, -300, self.ADMIN, reason="แก้ไข")
        req = wt.request_withdrawal(self.CHAT, 111, 1000)
        wt.approve_withdrawal(self.CHAT, req.data["request_id"], self.ADMIN)
        self.assertEqual(wt.recompute_balance(self.CHAT, 111), self._balance(111))
        self.assertEqual(wt.recompute_balance(self.CHAT, 222), self._balance(222))

    # ==================== Debt integration (atomic) ====================

    def _make_debt_entry(self, debtor_name="สมชาย", amount_satang=500):
        result = dl.add_entry(self.CHAT, debtor_name, amount_satang, recorded_by=self.ADMIN,
                               item_description="ข้าวกล่อง")
        self.assertTrue(result.ok)
        return result.entry_id

    def test_debt_payment_atomic_success(self):
        entry_id = self._make_debt_entry(amount_satang=500)
        self._fund(111, 1000)
        result = wt.pay_debt_with_wallet(self.CHAT, entry_id, 111)
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(111), 500)  # wallet debited
        entry = dl.get_entry(entry_id)
        self.assertEqual(entry["status"], dl.EntryStatus.PAID.value)  # AND debt marked paid
        self.assertEqual(entry["paid_by"], 111)

    def test_debt_payment_insufficient_balance_changes_nothing(self):
        """Atomicity on the failure path: if the wallet debit can't
        happen, the debt entry must NOT be marked paid either."""
        entry_id = self._make_debt_entry(amount_satang=500)
        self._fund(111, 100)  # not enough
        result = wt.pay_debt_with_wallet(self.CHAT, entry_id, 111)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(self._balance(111), 100)  # untouched
        entry = dl.get_entry(entry_id)
        self.assertEqual(entry["status"], dl.EntryStatus.UNPAID.value)  # untouched

    def test_debt_payment_already_paid_entry_fails(self):
        entry_id = self._make_debt_entry(amount_satang=500)
        self._fund(111, 1000)
        self.assertTrue(wt.pay_debt_with_wallet(self.CHAT, entry_id, 111).ok)
        self._fund(222, 1000)
        second = wt.pay_debt_with_wallet(self.CHAT, entry_id, 222)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PAID")

    def test_debt_payment_nonexistent_entry_fails(self):
        self._fund(111, 1000)
        result = wt.pay_debt_with_wallet(self.CHAT, 999999, 111)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ENTRY_NOT_FOUND")

    def test_debt_payment_wrong_chat_fails(self):
        entry_id = self._make_debt_entry(amount_satang=500)
        self._fund(111, 1000, chat_id=2)
        result = wt.pay_debt_with_wallet(2, entry_id, 111)  # entry belongs to chat 1
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ENTRY_NOT_FOUND")

    def test_debt_payment_idempotency_replay(self):
        entry_id = self._make_debt_entry(amount_satang=500)
        self._fund(111, 1000)
        key = "debt-update-1"
        first = wt.pay_debt_with_wallet(self.CHAT, entry_id, 111, idempotency_key=key)
        self.assertTrue(first.ok)
        second = wt.pay_debt_with_wallet(self.CHAT, entry_id, 111, idempotency_key=key)
        self.assertTrue(second.ok)
        self.assertTrue(second.data.get("already_processed"))
        self.assertEqual(self._balance(111), 500)  # only debited once

    def test_debt_payment_by_someone_other_than_debtor_allowed(self):
        """wallet.py's own design note: paying with your own money is
        deliberately open to any member, not just the named debtor."""
        entry_id = self._make_debt_entry(debtor_name="สมชาย", amount_satang=500)
        self._fund(222, 1000)  # 222 is not "สมชาย" but pays anyway
        result = wt.pay_debt_with_wallet(self.CHAT, entry_id, 222)
        self.assertTrue(result.ok)
        self.assertEqual(self._balance(222), 500)

    # ==================== Concurrency / race conditions ====================

    def test_concurrent_withdrawals_never_go_negative(self):
        """Requirement: no Negative Balance / no Double Spend under
        concurrency. Fund one wallet with 1,000 baht, fire 20 threads
        each requesting a 100-baht withdrawal at once -- exactly 10
        should succeed (the other 10 must see INSUFFICIENT_BALANCE),
        and the ledger must reconcile exactly, with the balance never
        allowed below zero at the DB level (CHECK constraint + atomic
        conditional UPDATE in wallet._debit)."""
        self._fund(111, 100000)  # 1,000 บาท
        results = []
        lock = threading.Lock()

        def attempt():
            r = wt.request_withdrawal(self.CHAT, 111, 10000)  # 100 บาท each
            with lock:
                results.append(r.ok)

        threads = [threading.Thread(target=attempt) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = sum(1 for ok in results if ok)
        self.assertEqual(successes, 10)
        self.assertEqual(self._balance(111), 0)
        self.assertGreaterEqual(wt.recompute_balance(self.CHAT, 111), 0)
        # ledger must reconcile: recompute_balance ignores pending rows,
        # and every successful withdrawal here is 'pending' (not yet
        # admin-approved), so the reconstructed total is the original
        # deposit minus nothing -- the *live* balance (already decremented
        # by the holds) is what we already asserted is exactly 0 above.

    def test_concurrent_transfers_never_go_negative(self):
        self._fund(111, 50000)  # 500 บาท
        results = []
        lock = threading.Lock()

        def attempt(recipient):
            r = wt.transfer(self.CHAT, 111, recipient, 10000)  # 100 บาท each
            with lock:
                results.append(r.ok)

        threads = [threading.Thread(target=attempt, args=(200 + i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = sum(1 for ok in results if ok)
        self.assertEqual(successes, 5)  # only 5 * 100 = 500 fits
        self.assertEqual(self._balance(111), 0)
        total_received = sum(self._balance(200 + i) for i in range(10))
        self.assertEqual(total_received, 50000)


if __name__ == "__main__":
    unittest.main()