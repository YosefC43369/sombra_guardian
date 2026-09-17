# Example workflows

Workflow definitions are data files. The engine loads `.json` by default
(no extra dependency) and also `.yaml`/`.yml` when PyYAML happens to be
installed, and `.py` files exposing `WORKFLOWS = [ {...}, ... ]`.

Ship a definition by dropping it into `workflows/definitions/` (loaded at
startup). The two files here are examples — both are `enabled: false` so they
do nothing until you turn them on.

## Fields

| field | meaning |
|-------|---------|
| `name` | unique id, used by `/workflow ... <name>` |
| `trigger.event` | the event that fires it (e.g. `incident.created`) |
| `conditions` | list of `{field, operator, value}`, all must pass (AND) |
| `actions` | ordered action names to run |
| `enabled` | start enabled? (persisted state overrides this at runtime) |
| `max_retries` | per-action retries on failure |
| `timeout_seconds` | whole-run timeout → `TIMEOUT` state |
| `cooldown_seconds` + `dedup_fields` | idempotency window |
| `max_depth` | loop guard on event chains |

Operators: `equals, not_equals, contains, not_contains, gt, gte, lt, lte,
in, not_in, exists, not_exists, regex` (regex is length-capped and rejects
nested-quantifier ReDoS patterns).

Built-in actions: `log_event, send_message, send_admin_alert, create_incident,
update_incident, create_evidence, run_detection, generate_report`. Plugins can
add more (see `../plugin_example/`).

## Manage at runtime (admin only)

```
/workflow list
/workflow show example-critical-incident
/workflow enable example-critical-incident
/workflow disable example-critical-incident
/workflow history
/workflow status
```
