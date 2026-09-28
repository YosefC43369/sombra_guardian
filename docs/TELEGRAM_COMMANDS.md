# Telegram Commands

Module: `behavioral_intelligence/telegram/` (§39–40).

## Registration

```python
from behavioral_intelligence.telegram import register_all
register_all(application)     # adds command handlers + inline-callback handler
```

`register_all` is a no-op (returns 0) if `python-telegram-bot` is unavailable, so
importing the package never hard-requires the bot library.

## Commands

| command | shows |
|---------|-------|
| `/behavior <entity> program=<id>` | the full compact summary (§40) |
| `/activity <entity> program=<id>` | rate, peak window, bursts, gaps |
| `/heatmap <entity> program=<id>` | hottest UTC hour×weekday cell |
| `/timeline <entity> program=<id>` | recent timeline events |
| `/languages <entity> program=<id>` | language mix + switching frequency |
| `/topics <entity> program=<id>` | top terms |
| `/hashtags <entity> program=<id>` | top hashtags |
| `/domains <entity> program=<id>` | top domains |
| `/interactions <entity> program=<id>` | edges + reciprocity |
| `/anomalies <entity> program=<id>` | deviation score + flagged anomalies |
| `/changes <entity> program=<id>` | change points & migrations |
| `/baseline <entity> program=<id>` | 30-day baseline |
| `/behavior_report <entity> program=<id>` | full markdown report (truncated to fit) |

Arguments: the first bare token is the target entity; `program=<id>` names an
authorized `scope_policy` program; `tz=<hours>` sets a display offset.

## Authorization

These commands operate on account/person-level behaviour, which is **fail-closed**.
Without an authorized `program=<id>` (and person scope set for it) the gate DENIES
and the user is told exactly why. **Telegram admin is never sufficient on its own**
— the same rule the `entity_fusion` gate enforces.

## Example output (`/behavior`)

```
🔍 Behavioral Intelligence
Entity: @username
Observation period: 2026-01-01 → 2026-09-28
Public observations: 1,482
Platforms: 7
Languages: th 61% · en 34% · other 5%
Peak activity: 19:00–23:00 UTC
Top topics: osint, cybersecurity, cloud, kubernetes, threat
Anomaly: 34/100 (minor deviation) (deviation from baseline, not a threat score)
Confidence: 0.87
Evidence: 17 independent public source(s)
Limitations: reflects only publicly observed data; describes activity patterns,
not the person.
```

## Inline keyboards

`keyboards.section_keyboard` / `format_keyboard` build section and report-format
selectors; `callbacks.make_handler` re-authorizes on every button press (a tap is
not a standing grant) and edits the message with the result.
