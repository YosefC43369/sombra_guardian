# Blue Team v0.8 admin guide

All commands work inside a group; a group is its own tenant. A **chat admin** is
OWNER of that tenant (may write); reads are ADMIN. Output is plain text with IOCs
defanged.

## `/intel` — Threat Intel / IOC
| Command | Role | What |
|---|---|---|
| `/intel status` · `stats` | ADMIN | totals, coverage, sightings |
| `/intel feeds` | ADMIN | feed list: license/enabled/last-status |
| `/intel lookup <ioc>` | ADMIN | check a URL/domain/ip/hash against the index |
| `/intel sightings <ioc>` | ADMIN | recent sightings |
| `/intel export [type]` | ADMIN | STIX 2.1-lite bundle |
| `/intel sync [feed]` | OWNER | sync one/all enabled feeds |
| `/intel add <ioc> [type]` | OWNER | add a local IOC |
| `/intel del <ioc>` | OWNER | remove a local IOC |
| `/intel whitelist add\|del\|list <value>` | OWNER | never-block list |
| `/intel health` | ADMIN | engine size, failing feeds |

## `/rule` — Detection-as-Code
| Command | Role | What |
|---|---|---|
| `/rule list` · `show <id>` · `stats` | ADMIN | inventory / detail |
| `/rule lint <json>` | ADMIN | validate a rule body |
| `/rule history <id>` | ADMIN | version hash-chain |
| `/rule backtest <id>` | ADMIN | match rate over stored samples |
| `/rule import <json>` · `new` | OWNER | add/replace a rule (starts disabled) |
| `/rule pack` | OWNER | load the 37-rule starter pack (as shadow) |
| `/rule shadow\|canary\|enable\|disable <id>` | OWNER | lifecycle |
| `/rule rollback <id> <ver>` | OWNER | restore a version |
| `/rule delete <id>` | OWNER | remove a rule |

Promotion path: import → **shadow** (evaluates, no action) → **canary** (listed
chats) → **enabled**. Watch `/rule stats` between steps.

## `/posture` — Security Posture & report
| Command | Role | What |
|---|---|---|
| `/posture status` · `score` | ADMIN | grade + score + coverage |
| `/posture explain` | ADMIN | biggest drags + remediation |
| `/posture whatif <ctrl>=<status>` | ADMIN | preview a change |
| `/posture trend` | ADMIN | score over time |
| `/posture portfolio` | ADMIN | multi-group summary |
| `/posture report [html\|md\|json\|csv\|pdf] [client\|internal]` | OWNER | build + seal a report |
| `/posture verify <report_id>` | ADMIN | re-hash a report vs the sealed SHA-256 |
| `/posture brand name\|color\|footer <v>` | OWNER | white-label |

## First-run checklist
1. Set `BLUETEAM_V08_ENABLED=true` (default). Optionally set an abuse.ch Auth-Key.
2. `/rule pack` then promote a few rules to `enabled`.
3. Confirm feeds: `/intel feeds`; `/intel sync` (or wait for the auto-sync).
4. `/posture status` and `/posture explain` to see gaps; enable the controls it names.
5. `/posture report client` for a customer-facing report.
