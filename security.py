""" 
security.py — Phase 1: Security Core

Adds, without touching bot.py's existing tables or data:
- Security Event System   (record_event)
- User Behavior Tracking  (user_behavior table)
- Risk Score              (0-100, LOW/MEDIUM/HIGH)
- Audit Log                (audit_log table)

Design constraints (Render Background Worker friendly):
- Standard library only (sqlite3, time, logging, enum).
- No network/API calls, no background threads or processes.
- Every public call does a small number of local SQLite writes and returns.
- Uses CREATE TABLE IF NOT EXISTS only; never touches bot.py's tables. 
- """