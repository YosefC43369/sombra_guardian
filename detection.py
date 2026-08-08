"""
detection.py — Phase 2: Advanced Detection Engine

Responsibilities (and only these):
  - Advanced Anti-Spam (message burst, repeated characters, excessive emoji,
    repeated short messages)
  - Duplicate Message Detection
  - Anti-Link Engine (URL/domain detection, blocklist/allowlist)
  - Anti-Mention Spam
  - Smart Text Normalization

detection.py never talks to Telegram and never decides moderation actions
(delete/warn/mute) — that stays in bot.py. detection.py never stores
security events, risk scores or audit entries itself — it calls into
security.py, which owns that storage. All checks are local and synchronous:
no AI API, no external HTTP requests, no DNS lookups, standard library only.
"""