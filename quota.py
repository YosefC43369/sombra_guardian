"""
quota.py — Phase 4: AI Usage Quota

Daily per-user Gemini usage limits: regular members get a small daily
cap, admins get a much higher (or unlimited) cap, so Gemini API cost
stays predictable once billing is turned on.

Design constraints (matches security.py / analytics.py):
- Standard library only.
- No network/API calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; never touches other modules' tables.
"""