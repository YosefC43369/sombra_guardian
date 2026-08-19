"""
debt_report.py — Formatting layer for the "เซ็นสินค้า" debt ledger.

Mirrors bb_report.py's / dashboard.py's read-only reporting pattern:
owns no tables of its own, performs no arithmetic of its own beyond
formatting numbers debt_ledger.py already computed, and makes no
network/LLM calls. Every baht figure shown here was produced by
debt_ledger.py's integer arithmetic (add_entry / summarize_by_debtor /
mark_debtor_paid) — this module only turns that data into
Thai-language, Telegram-ready text.

Standard library only. No dependency on gemini.py/OpenAI — this layer
must stay usable even if the AI provider is down (matches the
"AI is optional, arithmetic is not" split described in
debt_ledger.py's own docstring).
"""