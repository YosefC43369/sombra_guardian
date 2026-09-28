# Detection-as-Code rule-writing guide

Rules are **Sigma-lite JSON** (data, never code). Import with
`/rule import <json>`; lint with `/rule lint <json>`.

## Shape
```json
{
  "id": "scam_example",
  "title": "Example scam",
  "level": "high",                       // info|low|medium|high|critical
  "tags": ["scam"],
  "attack": "financial-fraud",           // free ATT&CK-style tag for coverage
  "detection": {
    "sel_kw":  {"text_lower|contains": ["free money", "แจกเงิน"]},
    "sel_url": {"has_url": true},
    "condition": "sel_kw and sel_url"
  },
  "aggregation": {"type": "count", "gte": 5, "window_s": 60, "group_by": "user_id"},
  "cooldown_s": 300,
  "dedupe_field": "user_id"
}
```

## Selections
A selection is a map; **all** its field tests must pass (AND). Combine selections in
`condition` with `and`, `or`, `not`, parentheses, and `all of sel_*` / `1 of sel_*`
(glob over selection names, `them` = all).

## Fields (record vocabulary)
`text`, `text_lower`, `text_len`, `urls`, `domains`, `registrable_domains`,
`url_count`, `has_url`, `user_id`, `is_new_member`, `account_age_days`,
`has_username`, `reply_to_is_admin`, `mention_count`, `url_entity_count`,
`emoji_count`, `is_forward`, `forward_from`.

**Match keywords against `text_lower` with lowercase needles** so the Aho-Corasick
prefilter and the predicate agree.

## Modifiers (`field|mod|mod`)
`contains`, `startswith`, `endswith`, `eq` (default), `re` (regex, ReDoS-linted),
`gt`/`gte`/`lt`/`lte` (numeric), `lower`, `all` (every value must match), `b64`.
A bare boolean value on a key with no modifier tests truthiness (`has_url: true`).

## Aggregation (stateful)
`type`: `count` or `distinct` (of `field`) over `window_s`, grouped by `group_by`;
fires when the windowed value ≥ `gte`. Backed by per-key time-window ring buffers.

## Lifecycle
`disabled → shadow → canary → enabled` (and back). **shadow** evaluates and logs but
takes no action (safe backtest in production); **canary** fires only in listed chats
(`/rule canary <id> <chat_id…>`); **enabled** fires everywhere. Every change bumps a
hash-chained version (`/rule history`), and `/rule rollback <id> <ver>` restores one.

## Limits & safety
- Condition AST node budget (`BLUETEAM_DAC_MAX_NODES`, default 500).
- Regex is length-capped and rejected if it has a nested quantifier `(x+)+`.
- A rule exceeding its per-message time budget repeatedly is circuit-broken (skipped)
  until it cools down.
- Unknown fields/modifiers compile to a constant-False test (fail-closed).
- Use `cooldown_s` + `dedupe_field` to avoid reporting one incident many times.

## Test before enabling
`/rule lint <json>` → fix problems → `/rule import` → leave in **shadow** and watch
`/rule stats` and `/rule backtest <id>` → promote to `canary` → `enabled`.
