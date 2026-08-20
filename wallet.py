"""
wallet.py — Wallet / Payment / Transaction Ledger (data layer)

Per-chat internal wallet for each Telegram user: balance, deposits,
withdrawals, member-to-member transfers, payment requests ("bills"),
and a full transaction ledger. Wired into the existing "เซ็นสินค้า"
debt ledger (debt_ledger.py) so an unpaid /debt entry can be settled
straight out of a member's wallet balance.

CORE INVARIANT (matches debt_ledger.py's own): every baht figure this
module produces comes from plain Python integer arithmetic over
`amount_satang` (1 บาท = 100 สตางค์, INTEGER — never float). The wallet
balance is NEVER written directly; every change to `wallets.balance_satang`
happens inside the same DB transaction as a new (or newly-settled)
`wallet_transactions` row, so the ledger can always reconstruct the
balance from scratch — see `recompute_balance()` at the bottom, used
only for auditing/tests, never on any hot path.

Design constraints (matches security.py / debt_ledger.py / scope_policy.py
/ findings.py):
- Standard library only (sqlite3, time, json, logging, dataclasses,
  enum, decimal, typing), with ONE deliberate exception: debt_ledger.py
  is imported, but ONLY inside pay_debt_with_wallet(), so that a debt
  settlement and the matching wallet debit commit as a single atomic
  SQLite transaction (Requirement #8). No other function in this file
  touches debt_ledger.py.
- No network/API calls, no LLM calls, no background threads. A real
  Payment Gateway is NOT guessed here — see payment_provider.py for the
  abstraction seam; today every deposit/payment is settled internally
  and requires an explicit admin confirmation (Requirement: "ห้ามถือว่า
  การกดปุ่มหรือส่งข้อความว่า 'โอนแล้ว' เป็นหลักฐานการชำระเงินจริง").
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table (via write_audit_log) — never a second database file.
- Wallets are scoped per (chat_id, user_id), NOT globally per user —
  this matches every other feature in this bot (debt_entries, findings,
  scope_policy, security are all chat_id-scoped) and keeps an admin's
  manual-adjustment/withdrawal-approval power (which is itself only
  ever checked per-chat via app.py's is_admin()) from ever reaching a
  balance outside the chat where that admin actually has authority.
  This is a deliberate interpretation of the task spec (which listed
  only "Telegram User ID" as the wallet key) in favor of consistency
  with the rest of the codebase — flagged explicitly for review.
- Every mutating public function opens exactly one connection, runs
  `BEGIN IMMEDIATE` (acquires SQLite's write lock up front rather than
  on first write), and commits or rolls back as a unit — this is what
  makes concurrent /transfer, /withdraw, and "pay with wallet" taps
  safe against double-spending: a balance debit is always an atomic
  conditional UPDATE (`WHERE balance_satang >= ?`), never a
  read-then-write pair a second writer could interleave with.
- `idempotency_key` (optional, usually Telegram's own `update.update_id`)
  lets a duplicate-delivered callback or a double-tapped confirm button
  replay safely: the second call finds the already-recorded transaction
  and returns it instead of creating a second one.
"""

import time
import json
import sqlite3
import logging
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Dict, List, Optional

from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.wallet")

MAX_RAW_AMOUNT_LEN = 32      # sanity cap before we even try Decimal()
MAX_TX_AMOUNT = Decimal("1000000")  # 1,000,000 บาท per single operation
DEFAULT_HISTORY_PAGE_SIZE = 10
CONN_TIMEOUT_SECONDS = 30    # let concurrent writers wait out BEGIN IMMEDIATE instead of erroring


class TxType(str, Enum):
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    TRANSFER_OUT = "transfer_out"
    TRANSFER_IN = "transfer_in"
    PAYMENT = "payment"
    REFUND = "refund"
    DEBT_PAYMENT = "debt_payment"
    ADJUSTMENT = "adjustment"
    
    
class TxStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    
    
class WithdrawalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    CANCELLED = "cancelled
    
    
class PaymentStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


VALID_WITHDRAWAL_STATUSES = {e.value for e in WithdrawalStatus}
VALID_PAYMENT_STATUSES = {e.value for e in PaymentStatus}


@dataclass
class OpResult:
    ok: bool
    reason: str = ""
    detail: str = ""
    data: dict = field(default_factory=dict)


class _Abort(Exception):
    """Internal control-flow only: raised inside a `with _tx() as conn:`
    block to trigger a rollback, caught immediately outside it and
    turned into an OpResult. Never escapes a public function."""
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=CONN_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None  # manual transaction control (BEGIN IMMEDIATE below)
    return conn
    
    
class _Tx:
    """Opens one connection, BEGIN IMMEDIATE (acquire the write lock up
    front), commit on clean exit, rollback on any exception. Every
    public mutating function below does its work inside `with _tx() as
    conn:` instead of hand-rolling try/commit/rollback each time."""
    
    def __enter__(self):
        self.conn = _conn()
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn
        
    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.commit()
        else:
            try:
                self.conn.rollback()
            except sqlite3.Error:
                pass
        self.conn.close()
        return False  # never suppress the exception
        
        
def _tx():
    return _Tx()
    
    
def wallet_db_init() -> None:
    """Creates the Wallet/Ledger tables only. Idempotent: safe on every
    process start, never resets or drops data. Never touches bot.py's,
    security.py's, or debt_ledger.py's tables."""
    conn = _conn()
    conn.execute("BEGIN")
    conn.execute("""CREATE TABLE IF NOT EXISTS wallets (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        balance_satang INTEGER NOT NULL DEFAULT 0 CHECK (balance_satang >= 0),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS wallet_transactions (
        transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount_satang INTEGER NOT NULL,
        balance_before_satang INTEGER NOT NULL,
        balance_after_satang INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed',
        reference_id TEXT,
        counterparty_user_id INTEGER,
        reason TEXT,
        metadata TEXT,
        idempotency_key TEXT,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wtx_chat_user "
        "ON wallet_transactions (chat_id, user_id, transaction_id DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wtx_chat_status "
        "ON wallet_transactions (chat_id, status)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_wtx_idempotency "
        "ON wallet_transactions (chat_id, idempotency_key) "
        "WHERE idempotency_key IS NOT NULL"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS withdrawal_requests (
        request_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        amount_satang INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        transaction_id INTEGER,
        requested_at INTEGER NOT NULL,
        decided_by INTEGER,
        decided_at INTEGER,
        reason TEXT
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wreq_chat_status "
        "ON withdrawal_requests (chat_id, status)"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS payment_requests (
        payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        requested_by INTEGER NOT NULL,
        payer_user_id INTEGER,
        amount_satang INTEGER NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        provider TEXT NOT NULL DEFAULT 'internal_wallet',
        provider_ref TEXT,
        transaction_id INTEGER,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        paid_at INTEGER
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pay_chat_payer_status "
        "ON payment_requests (chat_id, payer_user_id, status)"
    )
    # Lightweight opportunistic username -> user_id cache, populated by
    # remember_user() (called from app.py's handle_message for every
    # text message, and from every wallet command handler). Telegram's
    # Bot API has no endpoint to resolve an arbitrary @username to a
    # user_id, so /transfer @username and /payment @username only work
    # for members this bot has already seen speak in the same chat --
    # /transfer and /payment also accept Reply-to-message instead (same
    # convention /mute and /unmute already use), which always works.
    conn.execute("""CREATE TABLE IF NOT EXISTS wallet_known_users (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT,
        display_name TEXT,
        last_seen_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wku_chat_username "
        "ON wallet_known_users (chat_id, username COLLATE NOCASE)"
    )
    conn.commit()
    conn.close()
    logger.info("WALLET DATABASE: OK")


# ---------------- Money helpers ----------------
# (Deliberately duplicated from debt_ledger.py rather than imported --
# every data-layer module in this repo (security/quota/scope_policy/
# findings/debt_ledger) only ever imports `security`, never each other;
# keeping that pattern means this module still loads/tests in complete
# isolation from debt_ledger.py, same as debt_ledger.py itself must
# keep working if some *other* module is broken.)

def parse_amount_to_satang(raw: Optional[str]) -> Optional[int]:
    """Parses user-supplied text into a positive integer number of
    satang. Returns None (never raises) for missing/non-numeric/zero/
    negative/absurdly-large input -- callers turn None into a Thai
    validation-error reply. The only place free-text money is parsed;
    every other function in this module only moves an already-validated
    int around."""
    if raw is None:
        return None
    text = raw.strip().replace(",", "")
    if not text or len(text) > MAX_RAW_AMOUNT_LEN:
        return None
    try:
        amount = Decimal(text)
    except (InvalidOperation, ValueError):
        return None