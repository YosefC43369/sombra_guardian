# Group SOC — Security & Privacy

The Group SOC is a **defensive (Blue Team) platform only**. It observes, correlates and
triages; it never attacks, scans, or exfiltrates.

## Hard boundaries (by construction)
- **No shell execution, no untrusted-file execution, no code eval.** The subsystem is
  pure Python over sqlite; it never spawns processes or evaluates content.
- **No automatic external network calls.** Threat-intel enrichment is OFF by default
  (`SOC_INTEL_ENRICHMENT_ENABLED=false`) and, when enabled, uses only a **local** IOC
  cache — member data never leaves the bot.
- **No Telegram-permission bypass.** The SOC records containment *intent*; any actual
  restrict/ban stays with the existing moderation/blueteam layer and the bot's real
  admin rights. `/soc` is admin-gated via the platform's `is_admin`.
- **No unauthorized data collection.** Only events the platform already emits are ingested.

## Privacy by default (rule §17)
- **User ids → salted hashes** (`util.hash_id`, salt from `SOC_HASH_SALT`). Raw ids never
  land in a content field; a watched user is stored as its hash.
- **Message text → hash + length** (`content_hash`, `content_len`). Raw text and
  usernames are dropped at the normalization boundary and never persisted
  (`SOC_REDACT_MESSAGE_TEXT=true`). This is enforced and tested (`test_normalization.py`).
- **Indicators are defanged** everywhere they are stored or rendered (`util.defang`), so a
  stored/echoed value can never be an accidental live link.
- **Data minimization + retention**: only structural/aggregate context is kept; old
  events/signals/timeline/audit rows are purged on a retention schedule.
- **Access logging**: every state change is written to `soc_audit_log` with the actor hash.

## Analytic honesty (rule §8/§13)
- Confidence and severity are **analytic signals, not proof of intent**. Signals carry an
  explicit `analytic_state` (`observed → correlated → suspicious → confirmed`); the SOC
  never auto-marks something `confirmed`. Every generated story appends the caveat
  *"Confidence is an analytical signal, not proof of malicious intent."*
- A watchlist entry is a **monitoring target, not a verdict**.

## Failure isolation (rule §15/§21)
- The bus handler (`on_event`) and every pipeline stage/correlator/detector is wrapped so
  a SOC error can **never** break the moderation/event flow that produced the event.
- Ingest is **idempotent** (`event_id` PK), so duplicated deliveries never double-count.
- The ingest queue is **bounded** (drop-oldest backpressure), so a burst can't exhaust memory.

## Default-off posture
Deploying the code changes nothing: the master switch is off, and even with it on each
group is inactive until an admin runs `/soc on`.
