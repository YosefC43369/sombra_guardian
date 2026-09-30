# Operations

## Enabling

1. Migrations run at bot startup (`migrations/m0008_cve_tracker.py`).
2. Set `CVE_TRACKER_ENABLED=true`. For usable rate limits add `CVE_NVD_API_KEY`
   and (to enable GitHub) `CVE_GITHUB_TOKEN`.
3. Restart the bot. The loop starts in `post_init` (`cve_task`), does its first
   fetch after a short delay, then every `CVE_POLL_INTERVAL` seconds.
4. In each group, an admin runs `/cve_subscribe <filters>`.

Startup never blocks the bot: if the subsystem is disabled the loop is a no-op,
and any error during a round is logged and the next tick proceeds.

## Startup sequence

```
load config → ensure schema (migration or ensure_schema) → build registry →
build AI adapter → build coordinator → (on start) build dispatcher →
start scheduler → first round after a short delay
```

## Subscriptions

```
/cve_subscribe                 → HIGH+ severity (default)
/cve_subscribe critical        → CRITICAL only
/cve_subscribe kev             → CISA KEV only
/cve_subscribe cvss 8          → CVSS ≥ 8.0
/cve_subscribe vendor microsoft
/cve_subscribe product apache
/cve_subscribe cwe CWE-79
/cve_subscribe keyword rce
/cve_subscribe critical noupdates   → critical, but no "CVE updated" alerts
/cve_unsubscribe               → stop alerts for this chat
/cve_preferences               → show current filters
```

The platform floor (`CVE_ALERT_MIN_CVSS` / `CVE_ALERT_MIN_SEVERITY`) applies
before any subscription. A KEV record always passes the floor (exploited in the
wild is never filtered out). Narrow subscriptions (specific vendor/product/CWE/
keyword) can still receive a below-floor CVE they explicitly asked for.

## Monitoring

* `/cve_status` (admin) — tracker/AI/alerts flags, poll interval, record count,
  subscriber count, per-source health, last round summary.
* `/cve_sources` — per-source health: 🟢 healthy / 🟡 degraded / 🔴 failing,
  last sync time, new count, last error.
* `/cve_stats` — totals, KEV count, severity breakdown, top vendors/CWEs,
  notification delivery counts.

Health rolls per-source `SourceState`: ≥ 2 consecutive failures → degraded,
≥ 5 → failing; a success resets it. Metrics (ingest counts, source/AI latency,
alert counts, queue depth, cache hit rate, duplicate rate) are in
`monitoring/metrics.py`. **Secrets are never logged** (rule §30).

## Manual sync

`/cve_sync` (admin) runs one round immediately and dispatches. `/cve_sync nvd`
syncs a single source. `/cve_test` (admin) renders a sample alert from the newest
CVE (or a synthetic one) without sending to subscribers — use it to check
formatting after a config change.

## Flood control

A CVE burst is paced by the throttler: a priority queue (KEV/critical first) with
a global send-rate token bucket. A Telegram `RetryAfter` pauses the whole queue
for its window and requeues the message (bounded attempts). Alerts are
idempotent, so a restart mid-burst never double-sends.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| No alerts | `CVE_TRACKER_ENABLED`/`CVE_ALERTS_ENABLED` off, or no subscriptions, or floor too high. Check `/cve_status`. |
| A source 🔴 failing | Check its `last_error` in `/cve_sources`. NVD/GitHub 429 → add an API key/token. |
| GitHub source absent | Needs `CVE_GITHUB_TOKEN`/`GITHUB_TOKEN`. |
| Summaries look terse / "AI ไม่พร้อมใช้งาน" footer | AI unavailable → deterministic fallback in use. Check the host AI config. |
| Duplicate-looking CVEs | Shouldn't happen — merge is keyed on CVE id. Check `cve_source_records` for the sources that contributed. |

## Graceful shutdown

`post_shutdown` calls `stop_tracker()` (sets the scheduler's stop event so it
persists checkpoints and drains) then cancels the `cve_task` with a bounded
timeout — no corrupted state, no leaked loop (rule §59).
