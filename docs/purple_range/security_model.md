# Purple Range — Security Model

Purple Range is an **authorized adversary-emulation / detection-validation** aid. It is
deliberately incapable of offensive action; the design makes the dangerous things
*impossible to express*, not merely discouraged.

## What it cannot do (enforced)
- **No command execution.** The package contains no `subprocess`, `os.system`, `os.popen`,
  `eval(`, `exec(`, or `pty`. A test (`test_security_posture.py`) fails the build if any
  are ever added.
- **No agents / no C2 / no remote control.** Nothing connects to a host or endpoint; there
  is no session/beacon channel, no task-to-agent dispatch.
- **No shell / surveillance commands.** `/range` has no `/shell`, `/exec`, `/cmd`,
  `shellaccess`, screenshot, file-manager, or "arbitrary command" surface (also test-guarded).
- **No authorization/scope/RoE bypass.** There is no `force`, `ignore_scope`, `bypass_roe`,
  or `admin_override` anywhere. The module does not import `scope_policy` (test-guarded).

## How authorization is actually enforced
Purple Range never holds the authorization path. The only way a plan becomes live is:

```
/range instantiate  →  purpleteam.create_exercise   (validates engagement ownership)
                    →  purpleteam.add_emulation      (records planned steps)
/pt start           →  purpleteam.start_exercise     (RE-CHECKS RoE via redteam.check_roe)
```

Starting an exercise — the point where RoE is enforced — is the existing `/pt` flow, not
Purple Range. So even a bug in Purple Range cannot run an unauthorized action, because
Purple Range cannot *start* or *execute* anything.

## Data safety
- Synthetic telemetry is tagged `source=purple_range_sim` and uses only non-routable /
  documentation values (`SIMULATED-HOST-NN`, RFC 5737 IPs, `.test` domains).
- The opt-in bus replay (`PURPLE_RANGE_SOC_BRIDGE_ENABLED`, default off) publishes only
  clearly-synthetic events; it never fabricates real detections or alerts.
- Sensitive actions are audited through the existing `security.write_audit_log`.

## Fail-closed
Every delegated call that cannot be proven authorized (missing engagement, wrong chat,
non-operational engagement) returns/raises a denial — never a silent allow.

## Posture summary
This module validates that **defenses detect** emulated adversary behaviour. It is not,
and cannot be turned into, a tool that performs that behaviour.
