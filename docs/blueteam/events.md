# Blue Team v0.8 event catalogue

All cross-module events are **frozen dataclasses** with a `schema_version`
(`blueteam/platform/events.py`). Fields are **add-only**: never remove or repurpose
one (that would break a subscriber or a persisted payload). Each event carries a
canonical `type` string that workflow triggers match, and `to_payload()` produces
the flat dict the existing workflow `EventBus` transports.

`schema_version = 1` (current).

| Event | `type` | Key fields | Notes |
|---|---|---|---|
| `FeedSynced` | `intel.feed_synced` | feed, added, updated, quarantined, total, duration_ms | emitted after a successful feed ingest |
| `FeedFailed` | `intel.feed_failed` | feed, reason, circuit_open | fetch/parse error or quarantine |
| `IocMatched` | `intel.ioc_matched` | chat_id, user_id, ioc_type, **value_defanged**, confidence, severity, feeds, subject | value is **always defanged**; `subject` = sha256 prefix of the canonical value |
| `RuleMatched` | `rule.matched` | chat_id, user_id, rule_id, rule_title, level, attack, mode, subject | `mode` ∈ shadow/canary/enabled |
| `RuleStateChanged` | `rule.state_changed` | rule_id, old_state, new_state, actor, reason | lifecycle transition |
| `PostureSnapshotCreated` | `posture.snapshot_created` | tenant, chat_id, score, grade, coverage | on each snapshot |
| `PostureScoreDropped` | `posture.score_dropped` | tenant, chat_id, old_score, new_score, delta | when a snapshot drops ≥ threshold |
| `ReportGenerated` | `report.generated` | tenant, report_id, profile, fmt, sha256 | `profile` ∈ client/internal |

## Rules for payloads
- **Never** put a live IOC (raw URL/domain/IP) in a payload. `IocMatched` carries
  only `value_defanged` and a `subject` hash. This keeps event logs safe to store,
  forward, and show.
- Payloads are data, not commands. Subscribers treat external-origin fields
  (feed names, rule titles) as untrusted text.
- Adding a field is backward compatible; removing/renaming one is a breaking change
  and requires bumping `SCHEMA_VERSION` and documenting the migration here.
