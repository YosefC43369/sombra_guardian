# Configuration

Every setting is an environment variable read at call time via `envutil` (blank
values are treated as unset, so a committed `.env` with empty `CVE_*` keys never
breaks import). Nothing here stores a secret in source. Defaults are chosen so
the subsystem is safe and quiet out of the box.

## Master switches

| Variable | Default | Meaning |
|---|---|---|
| `CVE_TRACKER_ENABLED` | `false` | Master kill switch. Dormant unless `true`. |
| `CVE_DATABASE_PATH` | `bot.db` | sqlite file (shared with the bot). |
| `CVE_POLL_INTERVAL` | `300` | Seconds between polling rounds (min 30). |
| `CVE_DEFAULT_LANGUAGE` | `th` | Summary language. |

## Networking / concurrency / retries

| Variable | Default | Meaning |
|---|---|---|
| `CVE_MAX_CONCURRENT_REQUESTS` | `8` | Global in-flight fetch cap (semaphore). |
| `CVE_REQUEST_TIMEOUT` | `20` | Per-request timeout (s). |
| `CVE_MAX_RETRIES` | `4` | Retries per request on retryable errors. |
| `CVE_RETRY_BASE_DELAY` | `2.0` | Backoff base (s); full-jitter exponential. |
| `CVE_RETRY_MAX_DELAY` | `60.0` | Backoff ceiling (s). |
| `CVE_MAX_RESPONSE_BYTES` | `33554432` | Hard response-size cap (≤ 64 MiB). |
| `CVE_CACHE_TTL` | `900` | Generic cache TTL (s). |
| `CVE_USER_AGENT` | `SombraGuardian-CVETracker/1.0 …` | Outbound UA. |

## Per-source (replace `<SRC>` with `NVD`, `CVE_ORG`, `CISA_KEV`, `GITHUB_ADVISORY`, `VENDOR_ADVISORY`)

| Variable | Meaning |
|---|---|
| `CVE_<SRC>_ENABLED` | Enable/disable this source. |
| `CVE_<SRC>_BASE_URL` | Override the API/feed base URL (e.g. a mirror). |
| `CVE_<SRC>_RATE_LIMIT` | Requests/second budget for this source. |
| `CVE_<SRC>_CONCURRENCY` | Max in-flight requests for this source. |
| `CVE_<SRC>_TIMEOUT` | Per-request timeout for this source. |
| `CVE_<SRC>_BACKFILL_DAYS` | How far back a first/backfill sync reaches. |

Credentials / extras:

| Variable | Meaning |
|---|---|
| `CVE_NVD_API_KEY` (or `NVD_API_KEY`) | Raises the NVD rate ceiling. |
| `CVE_NVD_RESULTS_PER_PAGE` | NVD page size (default 200). |
| `CVE_GITHUB_TOKEN` (or `GITHUB_TOKEN`) | Enables the GitHub advisory source. |
| `CVE_GITHUB_PER_PAGE` | GitHub page size (default 100). |
| `CVE_VENDOR_FEEDS` | `name=url,name2=url2` list of vendor advisory feeds. |

NVD and GitHub default to a conservative unauthenticated rate; a token raises it.
The GitHub source is **disabled by default unless a token is present**.

## AI

| Variable | Default | Meaning |
|---|---|---|
| `CVE_AI_ENABLED` | `true` | Use AI for summaries (deterministic fallback otherwise). |
| `CVE_AI_PREFER_ROUTER` | `true` | Prefer `ai_router` over the single `gemini` client. |
| `CVE_AI_SUMMARY_MAX_CHARS` | `1400` | Cap on summary length (≤ 3500). |
| `CVE_AI_CACHE_TTL` | `86400` | Summary cache TTL (s). |
| `CVE_AI_MAX_REPAIR` | `1` | Retries after a failed validation before fallback. |
| `CVE_AI_MAX_INPUT_CHARS` | `12000` | Cap on structured input handed to the model. |
| `CVE_AI_TEMPERATURE` | `0.2` | Generation temperature. |

The AI **credentials and provider selection stay owned by the host project**
(`gemini.py` / `ai_router.py`); this subsystem never adds its own AI keys.

## Alerts

| Variable | Default | Meaning |
|---|---|---|
| `CVE_ALERTS_ENABLED` | `true` | Master alert switch. |
| `CVE_ALERT_MIN_CVSS` | `0.0` | Platform CVSS floor (KEV bypasses it). |
| `CVE_ALERT_MIN_SEVERITY` | `MEDIUM` | Platform severity floor. |
| `CVE_ALERT_SEND_RATE` | `0.7` | Global sends/second (flood safety). |
| `CVE_ALERT_SEND_DELAY` | `1.2` | Delay between sends in a burst (s). |
| `CVE_ALERT_MAX_PER_CYCLE` | `25` | Max alerts drained per scheduler tick. |
| `CVE_ALERT_MAX_SEND_RETRIES` | `4` | Retries for a failed Telegram send. |
| `CVE_ALERT_ADMIN_CHAT_ID` | `0` | Optional admin/SOC channel (gets all ≥ floor). |
| `CVE_ALERT_ADMIN_TOPIC_ID` | — | Topic id within that channel. |

## Retention (history tables only — CVE core records are never auto-deleted)

| Variable | Default (days) |
|---|---|
| `CVE_RETENTION_RAW_DAYS` | 180 (trims raw payloads, keeps provenance row) |
| `CVE_RETENTION_AI_DAYS` | 365 |
| `CVE_RETENTION_EVENT_DAYS` | 365 |
| `CVE_RETENTION_AUDIT_DAYS` | 730 |
| `CVE_RETENTION_NOTIFICATION_DAYS` | 365 |

A horizon of `0` means "keep forever".
