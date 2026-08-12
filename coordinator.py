"""
coordinator.py — Phase 8: Coordinator / Parallel Worker Agents

Sits between app.py's check_gemini_mention() and gemini.ask_gemini().
Every worker below is a thin wrapper around a function that already
exists in security.py / analytics.py / detection.py / news.py /
gemini.py / quota.py — nothing is re-implemented.

Design constraints:
  - LOW complexity -> identical to pre-Coordinator behavior: exactly one
    gemini.ask_gemini(question) call, no workers, no extra latency, no
    extra AI cost.
  - security/analytics workers are local SQLite reads: zero network
    calls, zero AI quota cost.
  - The only extra AI cost this file can introduce is (a) one
    classify_spam() call in the Detection Worker, gated by the existing
    quota.check_and_use_classifier_quota(), and (b) one verification
    pass for HIGH complexity requests only (toggleable, see
    COORDINATOR_VERIFICATION_ENABLED). The per-user ask quota
    (quota.check_and_use_quota) is checked exactly once by app.py,
    same as before this file existed.
  - One worker failing/timing out never fails the request — Coordinator
    always has a plain-answer fallback.
  - No shell/code execution, no dynamic dispatch by name-from-user-input:
    each worker calls one fixed, pre-existing, read-only function.
"""