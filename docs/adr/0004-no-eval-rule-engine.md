# ADR 0004 — No `eval`/`exec`/`compile` anywhere in the rule engine

**Status:** accepted (v0.8.0) · **Context:** Detection-as-Code engine, security

## Context
Rules are authored data that admins import (`/rule import <json>`) and that could,
in a future feature, be shared or pulled from a feed. The fastest-to-write engine
would translate a rule condition into a Python expression string and `eval` it.
That turns rule text into executable code — a code-injection sink and a sandbox-
escape risk — and it would violate the project's gติกา ("rules are data, never
Python; never use eval/exec/compile on rules").

## Decision
The engine **never** calls the builtins `eval`, `exec`, or `compile` on rule data.
The condition is tokenized by a hand-written lexer, parsed by a recursive-descent
parser into a small tagged-tuple AST (node budget enforced), and compiled to nested
closures. Field values are compared with ordinary Python operators and
`str`/`re` methods. Regex patterns are `re.compile`d (the stdlib regex compiler —
not the `compile` builtin, and not applied to rule *logic*) after a ReDoS lint.

A test (`test_blueteam_dac_core.py`) statically greps the engine source for bare
`eval(`/`exec(`/`compile(` builtin calls and fails if any appear.

## Consequences
- Rule import cannot execute arbitrary code, regardless of rule content.
- Unknown fields/modifiers compile to a constant-False test (fail-closed) instead of
  raising, so a malformed rule can't crash the pipeline.
- Trade-off: the engine supports only the documented Sigma-lite grammar, not
  arbitrary expressions. That's the point — the grammar is the security boundary.
