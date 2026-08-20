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