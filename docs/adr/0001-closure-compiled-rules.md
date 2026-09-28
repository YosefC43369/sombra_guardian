# ADR 0001 — Compile detection rules to closures, not an interpreter tree-walk

**Status:** accepted (v0.8.0) · **Context:** Detection-as-Code engine

## Context
Sigma-lite rules must be evaluated against every message. Two obvious designs:
(a) keep the parsed AST and walk it per event (an interpreter), or (b) compile the
AST once into a Python closure and call it per event.

## Decision
Compile once to a **closure**. `compile_ast` turns each node into a small lambda
that captures its children; a rule becomes one `predicate(record) -> bool`. Field
tests likewise compile to closures with their needles/patterns captured (regex is
`re.compile`d at rule-compile time, never per event).

## Consequences
- **Faster steady state**: no per-event dispatch on node type, no per-event regex
  compilation. Benchmarks: 37 rules over a message in ~54 µs (with the Aho-Corasick
  prefilter), ~18.6k msgs/s single-core.
- **No `eval`/`exec`/`compile`** of rule data (see ADR 0004): closures are built
  from a bounded AST we parsed ourselves, so rule text is never executed as code.
- **Bounded**: the parser enforces an AST node budget; a slow rule is additionally
  circuit-broken at runtime.
- Trade-off: the compiled predicate is opaque to introspection, so we keep the
  original rule body (versioned, hash-chained) as the source of truth and recompile
  on load. Debugging uses `/rule test` and `/rule lint`, which re-derive from the body.
