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