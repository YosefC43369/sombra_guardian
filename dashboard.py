"""
dashboard.py — Phase 6: Admin Dashboard

Read-only summary: pulls together security events, group analytics, and
Gemini usage from tables that security.py / analytics.py / quota.py
already own, formatted as one Thai report. No Telegram/network calls
here (matches security.py/analytics.py/quota.py) — the command handler
and admin-permission check live in app.py.
"""