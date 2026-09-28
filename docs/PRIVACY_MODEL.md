# Privacy & Data-Minimisation Model

Module: `behavioral_intelligence/configuration.py` (`PrivacyConfig`) and the
report layer (§34, §52).

## Data minimisation

Redaction is **on by default**. The engine keeps hashes and derived statistics and
drops raw text unless explicitly told to retain it.

| setting | env var | default | effect |
|---------|---------|---------|--------|
| `retain_raw_text` | `BEHAVIORAL_RETAIN_TEXT` | `false` | keep post text vs. hash only |
| `redact_pii_in_reports` | `BEHAVIORAL_REDACT_PII` | `true` | scrub PII in rendered reports |
| `mask_account_ids` | `BEHAVIORAL_MASK_ACCOUNTS` | `false` | hash account ids in reports |
| `max_sample_text_chars` | `BEHAVIORAL_MAX_SAMPLE_CHARS` | `240` | truncate any shown text |
| `evidence_ttl_days` | `BEHAVIORAL_EVIDENCE_TTL_DAYS` | `180` | evidence retention |
| `observation_ttl_days` | `BEHAVIORAL_OBS_TTL_DAYS` | `365` | observation retention |

`SQLiteStore.prune_observations(older_than)` enforces the TTL; `content_hash`
lets the engine dedupe and cache without retaining raw text. Account-id masking
in reports uses a SHA-256 prefix (`acct:xxxxxxxx`).

## Collection safety (§52)

The subsystem is **passive**. Providers do **not**:

- bypass authentication, paywalls or access controls
- use stolen sessions or cookies
- brute-force accounts or test passwords
- exploit or evade platform security controls

They **respect** `robots.txt` (`BEHAVIORAL_RESPECT_ROBOTS`), provider terms,
per-host rate limits (`BEHAVIORAL_RATE`/`BEHAVIORAL_BURST`), HTTP status codes and
timeouts. **No biometrics**: media analysis counts publicly-declared attachments,
performing no facial recognition or biometric identification.

## Credentials

All provider credentials come from the environment (spec §53). None are
hardcoded. The engine runs with zero configuration using safe defaults; env vars
only tune storage location, windows, privacy posture and provider limits.

## Authorization

Person/account behavioural analysis is fail-closed and requires an explicit
`allow_person_scope` tied to a reviewed `scope_policy` program — see
`EVIDENCE_MODEL.md` and `authorization.py`. Every gate decision is written to the
shared audit log when available.
