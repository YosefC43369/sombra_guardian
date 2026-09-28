# Telegram Commands

Package: `threat_actor_intelligence/telegram/`

Registered onto the bot in `app.py` via `register_all(app)` (collision-safe: it
skips any command already registered by another module, and a failure never
prevents the bot from starting). All commands are **read-only** public-CTI
queries; none carry a destructive action or expose secrets.

The analytical logic lives in `TAICommandService` (pure, returns rendered
strings — fully unit-tested without a running bot); the `async` handlers are thin
adapters.

## Commands

| Command | Arguments | Result |
|---|---|---|
| `/actor` | `<name\|alias>` | Actor summary: type, aliases, malware, campaigns, ATT&CK coverage, victimology, confidence. Falls back to alias candidates. |
| `/campaign` | `<name>` | Campaign summary: attributed actors, malware, IOC count, duration, confidence. |
| `/malware` | `<family>` | Malware family: category, aliases, platforms, known public sample-ref count, confidence. |
| `/ioc` | `<indicator>` | Stored IOC: defanged value, associated malware/campaign/actor, source count, related links. |
| `/attack` | `<T####\|name>` | ATT&CK technique: tactics, mitigations, related CAPEC, description. |
| `/capec` | `<CAPEC-##\|##>` | CAPEC pattern: abstraction, related ATT&CK techniques, CWEs. |
| `/report` | `<name> [type=actor\|campaign\|malware] [fmt=markdown\|html\|json\|csv]` | Full dossier in the requested format. |
| `/timeline` | `<actor\|campaign>` | Evidence-dated activity timeline. |
| `/actor_graph` | `<name> [fmt=json\|dot\|graphml\|gexf]` | Actor relationship graph export. |
| `/campaign_graph` | `<name> [fmt=json\|dot\|graphml\|gexf]` | Campaign relationship graph export. |
| `/ioc_report` | `<campaign name> [fmt=csv\|json]` | Campaign IOC table. |

## Inline keyboards

Actor / campaign / malware replies can carry pivot buttons encoded as
`tai:<action>:<id>` callback data (≤64 bytes), decoded by
`telegram.callbacks.dispatch` — e.g. Timeline, Graph (DOT), Malware, Campaigns,
Full report. `dispatch` is pure and unit-tested; `make_handler` wraps it for
python-telegram-bot.

## Examples

```
/actor APT29
/campaign SolarWinds Compromise
/malware SUNBURST
/ioc evil.example.com
/attack T1566
/capec 98
/report APT29 fmt=markdown
/timeline APT29
/actor_graph APT29 fmt=graphml
/ioc_report SolarWinds Compromise fmt=csv
```

## Guardrails in output

Every actor reply appends the standing note: *"Public-source CTI; aliases are not
identity; no attribution beyond cited sources."* Confidence is always shown as a
band + score. Replies are truncated to Telegram's message cap; use `/report` for
the full dossier.

## Registration

```python
from threat_actor_intelligence.telegram import register_all
register_all(app)     # returns the number of command handlers registered
```
