"""
debt_ledger.py — "เซ็นสินค้า" Outstanding-Balance Ledger (data layer)

Deterministic, offline record-keeping for "who signed for goods/items
and hasn't paid yet" (e.g. staff taking snacks/drinks on credit,
settled at the next payroll cycle). Each signed item is one row;
rows are summed by admin command (never guessed by an LLM) into a
per-person total for a given calendar-month window.

CORE INVARIANT: every baht figure this module ever returns comes from
plain Python integer arithmetic over `amount_satang` (1 บาท = 100
สตางค์, stored as INTEGER — never float, never a string that gets
`eval`'d or fed to an LLM to total up). gemini.py / OpenAI are never
imported here and no function in this file makes a network call —
that keeps this ledger correct and usable even if the AI provider
(gemini.py's GPT-5.6 Luna integration) is down, misconfigured, or
removed entirely (see app.py's /debt_summary handler for the optional,
best-effort AI formatting step, which only ever runs *after* this
module has already produced the final numbers).

Design constraints (matches security.py / quota.py / scope_policy.py /
findings.py):
- Standard library only (sqlite3, time, re, logging, dataclasses, enum,
  decimal, datetime, zoneinfo).
- No network/API calls, no LLM calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table (via write_audit_log) — no second database, never
  touches bot.py's or any other module's tables.
- All money in/out of this module is either a Decimal (input parsing)
  or an int number of satang (everywhere else). format_baht() is the
  only function that turns a satang amount into display text; callers
  that need a Telegram-ready message should go through debt_report.py
  instead of formatting baht themselves.
- Every date bucket ("which day/month does this entry belong to") is
  computed in Asia/Bangkok local time, not server/UTC time, so a
  signature made late at night in Thailand never lands in the wrong
  month just because the server clock is UTC.
"""