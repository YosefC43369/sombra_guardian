# Purple Range — Operator Guide

Purple Range is a **content + analytics layer** over the existing `purpleteam.py` engine.
It gives you a library of ATT&CK emulation plans, deterministic synthetic telemetry for
detection tuning, and a program-wide coverage view. It does **not** run anything on any
host — "emulation" here means records + synthetic data.

## Enabling it
1. Set `PURPLE_RANGE_ENABLED=true` (off by default).
2. In the group, the `/range` command is available to admins.

## The workflow

```
1. An engagement exists and is authorized        (existing redteam.py / /rt)
2. /range plans                                   browse the plan library
3. /range plan <code>                             inspect steps + expectations
4. /range instantiate <code> <engagement_id>      builds a purpleteam EXERCISE:
                                                   create_exercise + add_emulation per step
5. /pt start <exercise_id>                         START it — RoE is re-checked HERE
6. /range telemetry <technique>                    synthetic fixtures for tuning
7. /pt detect ...                                  record observed outcomes (existing)
8. /range coverage                                 program-wide ATT&CK coverage
9. /range snapshot                                 save a coverage point-in-time
```

Purple Range only performs steps 2–4, 6, 8, 9 (planning, synthetic telemetry, analytics).
Starting an exercise and recording detections stay with the existing `/pt` flow, so **RoE
enforcement is never in Purple Range's hands** — it cannot bypass it.

## Command reference

| Command | What it does | Gate |
|---|---|---|
| `/range plans` | list emulation plans (builtin + custom) | admin |
| `/range plan <code>` | plan detail: steps, techniques, expected telemetry/rules | admin |
| `/range instantiate <code> <eng_id>` | create a `purpleteam` exercise from the plan | admin |
| `/range telemetry <technique> [n]` | synthetic telemetry sample for a technique | admin |
| `/range expectations <technique>` | expected telemetry + detection rules | admin |
| `/range coverage` | program-wide ATT&CK coverage matrix | admin |
| `/range snapshot` | save a coverage snapshot | admin |
| `/range instantiations` | recent plan→exercise links | admin |
| `/range status` | module status/health | admin |

## Plans
Builtin plans ship as fixtures in `purple_range/plans/library/*.json`. Each step maps a
MITRE ATT&CK technique to its **expected telemetry** and **expected detection rules** —
the material a detection-tuning cycle compares against. Shipped plans:
`discovery-baseline`, `execution-scripting`, `credential-access-sim` (fully synthetic).

## Synthetic telemetry
`/range telemetry <technique>` shows the fixture events the generator would produce:
hostnames are `SIMULATED-HOST-NN`, IPs are RFC 5737 documentation ranges, domains use the
reserved `.test` TLD. Output is **deterministic** for a given seed so tuning is reproducible.
Nothing is read from, or written to, a real host.
