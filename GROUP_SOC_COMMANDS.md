# Group SOC — Commands (`/soc`)

All SOC commands are under one root, `/soc <sub> [args…]`, and are **admin-gated**
(the plugin registers `/soc` with `PermissionLevel.ADMIN`, enforced by the platform's
existing `is_admin`). General members cannot use it. Output is plain text; any indicator
is defanged.

The SOC is dormant until (1) `SOC_ENABLED=true` in the environment **and** (2) an admin
runs `/soc on` in the group.

## Overview / control
| Command | Action |
|---|---|
| `/soc` or `/soc overview` | volumes + open work summary |
| `/soc status` | master switch, per-group policy, capability flags, worker state |
| `/soc health` | worker/queue health + integration availability |
| `/soc metrics` | 24h KPIs (MTTA/MTTR), top producers |
| `/soc on` \| `/soc off` | activate / deactivate the SOC for this group |

## Events
| Command | Action |
|---|---|
| `/soc events` \| `/soc events recent` | recent normalized events |
| `/soc events search <type>` | events of a given type |
| `/soc events timeline <correlation_id>` | reconstructed timeline for a correlation |
| `/soc events <event_id>` | one event's detail |

## Alerts
| Command | Action |
|---|---|
| `/soc alerts` | open alerts (priority-sorted) |
| `/soc alert <id>` | alert detail |
| `/soc alert ack <id>` | acknowledge |
| `/soc alert suppress <id>` | suppress |
| `/soc alert escalate <id>` | escalate |
| `/soc alert resolve <id>` \| `close <id>` | resolve / close |
| `/soc alert assign <id> [<hash>]` | assign (defaults to caller) |

## Cases
`/soc cases` · `/soc case <id>` · `/soc case create <title>` · `/soc case assign <id>` ·
`/soc case note <id> <text>` · `/soc case close <id>`

## Incidents
`/soc incidents` · `/soc incident <id>` · `/soc incident create <class> <title>` ·
`/soc incident resolve <id>` · `/soc incident contain <id>` ·
`/soc incident timeline <id>` · `/soc incident story <id>`
(classes: spam_campaign, coordinated_activity, raid, impersonation, malicious_link,
ioc_exposure, permission_abuse, account_takeover, other)

## Investigation
`/soc investigate` · `/soc investigate open <title>` ·
`/soc investigate hypothesis <id> <text>` · `/soc investigate evidence <id> <kind> <ref>` ·
`/soc investigate conclude <id> <text>` ·
`/soc pivot actor <hash>` · `/soc pivot entity <kind> <key>` · `/soc pivot related <corr>`

## Watchlist (monitoring ≠ verdict)
`/soc watchlist` · `/soc watch <kind> <value>` · `/soc unwatch <kind> <value>`
(kinds: user, bot, domain, url, ip, hash, phrase, pattern, event_type)

## Reports
`/soc report daily` · `weekly` · `executive` · `technical` · `incident <id>`
