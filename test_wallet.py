"""
test_wallet.py — Unit test suite for wallet.py (Wallet / Payment /
Transaction Ledger) plus its one deliberate cross-module dependency,
debt_ledger.py's pay_debt_with_wallet() integration.

Same isolation pattern as test_scope_policy.py / test_findings.py:
every test gets a fresh tempfile SQLite DB, with security.DB_PATH,
wallet.DB_PATH, and debt_ledger.DB_PATH all patched to it (wallet.py's
pay_debt_with_wallet() locally imports debt_ledger, so debt_ledger's
own module-level DB_PATH must be patched too, exactly like app.py's
real startup wires all three modules to the same bot.db).
"""

import os
import time
import tempfile
import threading
import unittest

import security
import debt_ledger as dl
import wallet as wt

CHAT = 1

class WalletTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._db_path = path
        security.DB_PATH = path
        dl.DB_PATH = path
        wt.DB_PATH = path
        security.security_db_init()
        dl.debt_ledger_db_init()
        wt.wallet_db_init()
        
    def tearDown(self):
        try:
            os.remove(self._db_path)
        except OSError:
            pass
            
    # ---- fixture helpers ----
    
    def _fund(self, user_id, satang, admin=999, chat_id=CHAT):
        result = wt.admin_adjust(chat_id, user_id, satang, admin_id=admin, reason="seed")
        self.assertTrue(result.ok, result.reason)
        return result

    # ---- Wallet creation / balance ----
    
    def test_new_wallet_starts_at_zero(self):
        w = wt.get_wallet(CHAT, 100)
        self.assertEqual(w["balance_satang"], 0)
        self.assertEqual(w["chat_id"], CHAT)
        self.assertEqual(w["user_id"], 100)

    def test_wallet_is_scoped_per_chat(self):
        self._fund(100, 1000, chat_id=1)
        w_other_chat = wt.get_wallet(2, 100)
        self.assertEqual(w_other_chat["balance_satang"], 0)

    def test_get_wallet_is_idempotent_lazy_create(self):
        w1 = wt.get_wallet(CHAT, 100)
        w2 = wt.get_wallet(CHAT, 100)
        self.assertEqual(w1["balance_satang"], w2["balance_satang"])

    def test_parse_amount_to_satang_valid(self):
        self.assertEqual(wt.parse_amount_to_satang("50"), 5000)
        self.assertEqual(wt.parse_amount_to_satang("50.5"), 5050)
        self.assertEqual(wt.parse_amount_to_satang("1,000"), 100000)

    def test_parse_amount_to_satang_rejects_invalid(self):
        self.assertIsNone(wt.parse_amount_to_satang(None))
        self.assertIsNone(wt.parse_amount_to_satang(""))
        self.assertIsNone(wt.parse_amount_to_satang("0"))
        self.assertIsNone(wt.parse_amount_to_satang("-5"))
        self.assertIsNone(wt.parse_amount_to_satang("abc"))
        self.assertIsNone(wt.parse_amount_to_satang("99999999"))  # over MAX_TX_AMOUNT

    def test_parse_signed_amount_allows_negative(self):
        self.assertEqual(wt.parse_signed_amount_to_satang("-50"), -5000)
        self.assertEqual(wt.parse_signed_amount_to_satang("50"), 5000)
        self.assertIsNone(wt.parse_signed_amount_to_satang("-0"))

    def test_format_baht_whole_and_fractional(self):
        self.assertEqual(wt.format_baht(10000), "100 บาท")
        self.assertEqual(wt.format_baht(10050), "100.50 บาท")

    # ---- Deposit ----

    def test_deposit_request_does_not_credit_until_confirmed(self):
        result = wt.request_deposit(CHAT, 100, 5000)
        self.assertTrue(result.ok)
        self.assertEqual(result.data["transaction"]["status"], wt.TxStatus.PENDING.value)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 0)

    def test_deposit_confirm_credits_balance(self):
        req = wt.request_deposit(CHAT, 100, 5000)
        tx_id = req.data["transaction"]["transaction_id"]
        result = wt.confirm_deposit(CHAT, tx_id, admin_id=999)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 5000)

    def test_deposit_confirm_twice_fails(self):
        req = wt.request_deposit(CHAT, 100, 5000)
        tx_id = req.data["transaction"]["transaction_id"]
        wt.confirm_deposit(CHAT, tx_id, admin_id=999)
        second = wt.confirm_deposit(CHAT, tx_id, admin_id=999)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PROCESSED")
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 5000)  # not double-credited

    def test_deposit_reject_never_credits(self):
        req = wt.request_deposit(CHAT, 100, 5000)
        tx_id = req.data["transaction"]["transaction_id"]
        result = wt.reject_deposit(CHAT, tx_id, admin_id=999, reason="fake proof")
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 0)
        # cannot confirm a rejected deposit afterwards
        self.assertFalse(wt.confirm_deposit(CHAT, tx_id, admin_id=999).ok)

    def test_deposit_invalid_amount_rejected(self):
        self.assertFalse(wt.request_deposit(CHAT, 100, 0).ok)
        self.assertFalse(wt.request_deposit(CHAT, 100, -100).ok)

    def test_list_pending_deposits(self):
        wt.request_deposit(CHAT, 100, 1000)
        wt.request_deposit(CHAT, 200, 2000)
        pending = wt.list_pending_deposits(CHAT)
        self.assertEqual(len(pending), 2)

    # ---- Withdrawal ----

    def test_withdrawal_holds_funds_immediately(self):
        self._fund(100, 10000)
        result = wt.request_withdrawal(CHAT, 100, 3000)
        self.assertTrue(result.ok)
        # funds already left the spendable balance at request time
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 7000)

    def test_withdrawal_insufficient_balance(self):
        self._fund(100, 1000)
        result = wt.request_withdrawal(CHAT, 100, 5000)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 1000)

    def test_withdrawal_prevents_double_spend_via_second_request(self):
        self._fund(100, 5000)
        first = wt.request_withdrawal(CHAT, 100, 4000)
        self.assertTrue(first.ok)
        second = wt.request_withdrawal(CHAT, 100, 4000)
        self.assertFalse(second.ok)  # only 1000 satang left, held funds already gone

    def test_withdrawal_approve_finalizes_without_further_balance_change(self):
        self._fund(100, 10000)
        req = wt.request_withdrawal(CHAT, 100, 3000)
        result = wt.approve_withdrawal(CHAT, req.data["request_id"], admin_id=999)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 7000)
        req_row = wt.get_withdrawal_request(CHAT, req.data["request_id"])
        self.assertEqual(req_row["status"], wt.WithdrawalStatus.COMPLETED.value)

    def test_withdrawal_reject_refunds_held_amount(self):
        self._fund(100, 10000)
        req = wt.request_withdrawal(CHAT, 100, 3000)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 7000)
        result = wt.reject_withdrawal(CHAT, req.data["request_id"], admin_id=999, reason="no proof")
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 10000)  # refunded

    def test_withdrawal_cancel_by_requester_refunds(self):
        self._fund(100, 10000)
        req = wt.request_withdrawal(CHAT, 100, 2000)
        result = wt.cancel_withdrawal(CHAT, req.data["request_id"], user_id=100)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 10000)

    def test_withdrawal_cancel_by_someone_else_forbidden(self):
        self._fund(100, 10000)
        req = wt.request_withdrawal(CHAT, 100, 2000)
        result = wt.cancel_withdrawal(CHAT, req.data["request_id"], user_id=555)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FORBIDDEN")
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 8000)  # still held

    def test_withdrawal_double_approve_fails(self):
        self._fund(100, 10000)
        req = wt.request_withdrawal(CHAT, 100, 2000)
        wt.approve_withdrawal(CHAT, req.data["request_id"], admin_id=999)
        second = wt.approve_withdrawal(CHAT, req.data["request_id"], admin_id=999)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PROCESSED")

    def test_list_pending_withdrawals(self):
        self._fund(100, 10000)
        wt.request_withdrawal(CHAT, 100, 1000)
        wt.request_withdrawal(CHAT, 100, 1000)
        self.assertEqual(len(wt.list_pending_withdrawals(CHAT)), 2)

    # ---- Transfer ----

    def test_transfer_moves_balance_atomically(self):
        self._fund(100, 10000)
        result = wt.transfer(CHAT, 100, 200, 3000, note="lunch")
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 7000)
        self.assertEqual(wt.get_wallet(CHAT, 200)["balance_satang"], 3000)

    def test_transfer_insufficient_balance_moves_nothing(self):
        self._fund(100, 1000)
        result = wt.transfer(CHAT, 100, 200, 5000)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 1000)
        self.assertEqual(wt.get_wallet(CHAT, 200)["balance_satang"], 0)

    def test_self_transfer_rejected(self):
        self._fund(100, 10000)
        result = wt.transfer(CHAT, 100, 100, 1000)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SELF_TRANSFER_NOT_ALLOWED")

    def test_transfer_invalid_amount(self):
        self._fund(100, 10000)
        self.assertFalse(wt.transfer(CHAT, 100, 200, 0).ok)
        self.assertFalse(wt.transfer(CHAT, 100, 200, -100).ok)

    def test_transfer_idempotency_key_prevents_duplicate(self):
        self._fund(100, 10000)
        key = "update-12345"
        first = wt.transfer(CHAT, 100, 200, 1000, idempotency_key=key)
        second = wt.transfer(CHAT, 100, 200, 1000, idempotency_key=key)
        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertTrue(second.data.get("already_processed"))
        self.assertEqual(
            first.data["out_tx"]["transaction_id"],
            second.data["out_tx"]["transaction_id"],
        )
        # balance only moved once, not twice
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 9000)
        self.assertEqual(wt.get_wallet(CHAT, 200)["balance_satang"], 1000)

    def test_concurrent_transfers_cannot_double_spend(self):
        """Two threads race to transfer 700 satang each out of a 1000
        satang balance -- exactly one must succeed. This is the actual
        BEGIN IMMEDIATE + conditional UPDATE guarantee under real
        concurrency, not just an assertion about the code."""
        self._fund(100, 1000)
        results = []

        def worker():
            r = wt.transfer(CHAT, 100, 200, 700)
            results.append(r.ok)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 300)
        self.assertEqual(wt.get_wallet(CHAT, 200)["balance_satang"], 700)

    def test_concurrent_withdrawals_cannot_double_spend(self):
        self._fund(100, 1000)
        results = []

        def worker():
            r = wt.request_withdrawal(CHAT, 100, 700)
            results.append(r.ok)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 300)

    # ---- Payment requests ("bills") ----

    def test_create_and_pay_open_bill(self):
        self._fund(100, 10000)
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=1500,
                                          description="ค่าอาหาร")
        self.assertTrue(bill.ok)
        result = wt.pay_payment_request(CHAT, bill.data["payment_id"], payer_user_id=100)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 8500)
        self.assertEqual(wt.get_wallet(CHAT, 200)["balance_satang"], 1500)

    def test_pay_bill_targeted_to_specific_payer_forbids_others(self):
        self._fund(100, 10000)
        self._fund(300, 10000)
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500,
                                          payer_user_id=100)
        result = wt.pay_payment_request(CHAT, bill.data["payment_id"], payer_user_id=300)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FORBIDDEN")

    def test_pay_bill_self_payment_not_allowed(self):
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500)
        result = wt.pay_payment_request(CHAT, bill.data["payment_id"], payer_user_id=200)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "SELF_PAYMENT_NOT_ALLOWED")

    def test_pay_bill_twice_fails(self):
        self._fund(100, 10000)
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500)
        wt.pay_payment_request(CHAT, bill.data["payment_id"], payer_user_id=100)
        second = wt.pay_payment_request(CHAT, bill.data["payment_id"], payer_user_id=100)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "ALREADY_PROCESSED")

    def test_pay_bill_insufficient_balance(self):
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500)
        result = wt.pay_payment_request(CHAT, bill.data["payment_id"], payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")

    def test_cancel_bill_by_requester(self):
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500)
        result = wt.cancel_payment_request(CHAT, bill.data["payment_id"], actor_id=200)
        self.assertTrue(result.ok)

    def test_cancel_bill_by_stranger_forbidden(self):
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500)
        result = wt.cancel_payment_request(CHAT, bill.data["payment_id"], actor_id=555)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "FORBIDDEN")

    def test_cancel_bill_by_admin_allowed(self):
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500)
        result = wt.cancel_payment_request(CHAT, bill.data["payment_id"], actor_id=999,
                                            is_admin_actor=True)
        self.assertTrue(result.ok)

    def test_expired_bill_cannot_be_paid(self):
        self._fund(100, 10000)
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=500,
                                          expires_in_seconds=-1)  # already expired
        result = wt.pay_payment_request(CHAT, bill.data["payment_id"], payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "EXPIRED")

    def test_list_payment_requests_as_payer_and_requester(self):
        wt.create_payment_request(CHAT, requested_by=200, amount_satang=500, payer_user_id=100)
        wt.create_payment_request(CHAT, requested_by=200, amount_satang=700)  # open bill
        as_payer = wt.list_payment_requests(CHAT, 100, role="payer")
        as_requester = wt.list_payment_requests(CHAT, 200, role="requester")
        self.assertEqual(len(as_payer), 2)  # targeted-at-me + open-to-anyone
        self.assertEqual(len(as_requester), 2)

    # ---- Admin manual adjustment ----

    def test_admin_adjust_credit(self):
        result = wt.admin_adjust(CHAT, 100, 5000, admin_id=999, reason="bonus")
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 5000)

    def test_admin_adjust_debit(self):
        self._fund(100, 10000)
        result = wt.admin_adjust(CHAT, 100, -3000, admin_id=999, reason="correction")
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 7000)

    def test_admin_adjust_debit_below_zero_fails(self):
        self._fund(100, 1000)
        result = wt.admin_adjust(CHAT, 100, -5000, admin_id=999, reason="oops")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 1000)

    def test_admin_adjust_requires_reason(self):
        result = wt.admin_adjust(CHAT, 100, 1000, admin_id=999, reason="")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "REASON_REQUIRED")

    def test_admin_adjust_zero_amount_rejected(self):
        result = wt.admin_adjust(CHAT, 100, 0, admin_id=999, reason="x")
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INVALID_AMOUNT")

    def test_admin_adjust_records_full_audit_trail_fields(self):
        result = wt.admin_adjust(CHAT, 100, 2000, admin_id=999, reason="correction")
        tx = result.data["transaction"]
        self.assertEqual(tx["created_by"], 999)          # admin_id
        self.assertEqual(tx["user_id"], 100)              # target_user_id
        self.assertEqual(tx["amount_satang"], 2000)
        self.assertEqual(tx["reason"], "correction")
        self.assertIn("transaction_id", tx)
        self.assertIn("created_at", tx)

    # ---- Transaction history / admin views ----

    def test_transaction_history_pagination(self):
        self._fund(100, 100000)
        for _ in range(15):
            wt.transfer(CHAT, 100, 200, 100)
        page1 = wt.list_transactions(CHAT, 100, page=1, page_size=10)
        self.assertEqual(len(page1["items"]), 10)
        self.assertEqual(page1["total_pages"], 2)
        page2 = wt.list_transactions(CHAT, 100, page=2, page_size=10)
        self.assertEqual(len(page2["items"]), 6)  # 1 funding tx + 15 transfers = 16

    def test_transaction_history_newest_first(self):
        self._fund(100, 10000)
        wt.transfer(CHAT, 100, 200, 100)
        wt.transfer(CHAT, 100, 200, 100)
        items = wt.list_transactions(CHAT, 100)["items"]
        self.assertGreaterEqual(items[0]["transaction_id"], items[1]["transaction_id"])

    def test_admin_list_all_transactions_filters_by_user(self):
        self._fund(100, 10000)
        self._fund(200, 10000)
        result = wt.list_all_transactions_admin(CHAT, user_id=100)
        self.assertTrue(all(t["user_id"] == 100 for t in result["items"]))

    def test_recompute_balance_matches_stored_balance(self):
        self._fund(100, 10000)
        wt.transfer(CHAT, 100, 200, 3000)
        wt.admin_adjust(CHAT, 100, -500, admin_id=999, reason="fee")
        stored = wt.get_wallet(CHAT, 100)["balance_satang"]
        recomputed = wt.recompute_balance(CHAT, 100)
        self.assertEqual(stored, recomputed)

    # ---- Known-user cache / @username resolution ----

    def test_remember_and_resolve_username(self):
        wt.remember_user(CHAT, 100, username="somchai", display_name="Somchai")
        self.assertEqual(wt.resolve_username(CHAT, "somchai"), 100)
        self.assertEqual(wt.resolve_username(CHAT, "@somchai"), 100)
        self.assertEqual(wt.resolve_username(CHAT, "SOMCHAI"), 100)  # case-insensitive

    def test_resolve_unknown_username_returns_none(self):
        self.assertIsNone(wt.resolve_username(CHAT, "nobody"))

    # ---- Debt integration (pay_debt_with_wallet) ----

    def test_pay_debt_with_wallet_settles_atomically(self):
        self._fund(100, 10000)
        entry = dl.add_entry(CHAT, "สมชาย", 2000, recorded_by=999, item_description="ข้าวกล่อง")
        self.assertTrue(entry.ok)

        result = wt.pay_debt_with_wallet(CHAT, entry.entry_id, payer_user_id=100)
        self.assertTrue(result.ok)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 8000)
        self.assertEqual(dl.get_entry(entry.entry_id)["status"], dl.EntryStatus.UNPAID.value.replace(
            dl.EntryStatus.UNPAID.value, dl.EntryStatus.PAID.value))  # sanity: PAID

    def test_pay_debt_with_wallet_insufficient_balance_leaves_debt_unpaid(self):
        entry = dl.add_entry(CHAT, "สมชาย", 2000, recorded_by=999)
        result = wt.pay_debt_with_wallet(CHAT, entry.entry_id, payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "INSUFFICIENT_BALANCE")
        # debt must still be unpaid -- no half-succeeded state
        self.assertEqual(dl.get_entry(entry.entry_id)["status"], dl.EntryStatus.UNPAID.value)
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 0)

    def test_pay_debt_with_wallet_already_paid_entry_fails(self):
        self._fund(100, 10000)
        entry = dl.add_entry(CHAT, "สมชาย", 2000, recorded_by=999)
        dl.mark_entry_paid(entry.entry_id, actor_user_id=999)  # paid via the free /paid path
        result = wt.pay_debt_with_wallet(CHAT, entry.entry_id, payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ALREADY_PAID")
        # wallet was never touched
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 10000)

    def test_pay_debt_with_wallet_wrong_chat_not_found(self):
        self._fund(100, 10000)
        entry = dl.add_entry(CHAT, "สมชาย", 2000, recorded_by=999)
        result = wt.pay_debt_with_wallet(chat_id=999999, entry_id=entry.entry_id, payer_user_id=100)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "ENTRY_NOT_FOUND")

    def test_pay_debt_with_wallet_idempotency_key_prevents_double_debit(self):
        self._fund(100, 10000)
        entry = dl.add_entry(CHAT, "สมชาย", 2000, recorded_by=999)
        key = "debtpay-1"
        first = wt.pay_debt_with_wallet(CHAT, entry.entry_id, payer_user_id=100, idempotency_key=key)
        self.assertTrue(first.ok)
        second = wt.pay_debt_with_wallet(CHAT, entry.entry_id, payer_user_id=100, idempotency_key=key)
        self.assertTrue(second.ok)
        self.assertTrue(second.data.get("already_processed"))
        self.assertEqual(wt.get_wallet(CHAT, 100)["balance_satang"], 8000)  # debited once, not twice

    def test_pay_debt_with_wallet_creates_ledger_row(self):
        self._fund(100, 10000)
        entry = dl.add_entry(CHAT, "สมชาย", 2000, recorded_by=999)
        result = wt.pay_debt_with_wallet(CHAT, entry.entry_id, payer_user_id=100)
        tx = result.data["transaction"]
        self.assertEqual(tx["type"], wt.TxType.DEBT_PAYMENT.value)
        self.assertEqual(tx["amount_satang"], 2000)
        self.assertEqual(tx["reference_id"], str(entry.entry_id))

    # ---- Refund (withdrawal rejection / cancellation path) ----

    def test_refund_transaction_type_recorded_on_rejection(self):
        self._fund(100, 10000)
        req = wt.request_withdrawal(CHAT, 100, 3000)
        result = wt.reject_withdrawal(CHAT, req.data["request_id"], admin_id=999, reason="no proof")
        refund_tx = result.data["refund_transaction"]
        self.assertEqual(refund_tx["type"], wt.TxType.REFUND.value)
        self.assertEqual(refund_tx["amount_satang"], 3000)

    # ---- Money safety: no float, integer-only satang ----

    def test_balances_and_amounts_are_always_int(self):
        self._fund(100, 12345)
        w = wt.get_wallet(CHAT, 100)
        self.assertIsInstance(w["balance_satang"], int)
        bill = wt.create_payment_request(CHAT, requested_by=200, amount_satang=999)
        self.assertIsInstance(bill.data["payment_id"], int)


if __name__ == "__main__":
    unittest.main()