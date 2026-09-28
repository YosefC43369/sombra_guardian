# ADR 0003 — Posture trend from pre-aggregated rollups, never raw-event scans

**Status:** accepted (v0.8.0) · **Context:** Security Posture score & trend

## Context
Posture needs a current score and a trend over time, per group and across a
portfolio. The naive approach recomputes trend by scanning the raw event/detection
log for each request — cost grows with history and with the number of groups, and
couples the score to log retention.

## Decision
- The **current score** is computed from a `SignalsProvider` that reports each
  control's status from the bot's own **config/state** (e.g. is Link Guard enabled),
  not by scanning messages.
- Each snapshot writes an **hourly rollup** (`bt_posture_rollup`, running mean per
  `(chat, metric, hour)`). **Trend reads only rollups**, so its cost is O(hours),
  independent of message volume and of raw-log retention.

## Consequences
- Trend and portfolio queries are cheap and stable as history grows.
- The score reflects controls that are actually observable (ADR-adjacent gติกา: no
  claims about facts the Bot API can't see, e.g. admin 2FA).
- Rollups survive raw-log pruning, so retention policy and reporting are decoupled.
- Trade-off: rollup granularity is hourly; sub-hour movement is averaged. Fine for a
  posture trend (the signal is slow-moving by nature).
