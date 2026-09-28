# Interaction Analysis

Module: `behavioral_intelligence/social/` (§20–25).

Analyses **publicly observable** interactions. It records that A publicly
mentioned/replied to B — it never labels the relationship (friendship,
employment, criminal association). No private relationship is inferred from any
metric here.

## Networks

- `mention_network.build_network` (§21) — directed A→B edges from public
  mentions, with per-edge count, kind breakdown, first/last-seen, platform spread
  and sample evidence URLs; plus in/out degree and reciprocity.
- `reply_network.build_reply_network` (§22) — reply graph with in/out degree,
  reciprocity, conversation depth (via `thread_engine`) and activity
  concentration (Gini of out-degree).

## Interaction patterns (`interaction_patterns.py`, §20)

Interaction frequency, reciprocity, **response latency** (time between a post and
the reply to it, when both are observed), repeated-partner counts, and per-platform
distribution.

## Communities (`community_analysis.py`, §23)

Three algorithms over the undirected projection:

- `connected_components` — pure-stdlib union-find (always available).
- `label_propagation` — pure-stdlib, deterministic tie-break.
- `louvain` — via `networkx` when installed; **falls back** to label propagation
  with a recorded note otherwise.

Communities are only reported above minimum-sample thresholds (≥4 nodes, ≥4
edges); each reports members, internal/external edges, density and a
sample-size-aware confidence. Membership is a structural grouping of interaction,
never a claimed real-world affiliation.

## Lifecycle & migration (§24–25)

- `account_activity` — first/last/peak, rate, and observable profile changes
  (username/avatar/bio) from successive metadata snapshots, emitted as timeline
  events.
- `detect_migrations` — activity shifting from one platform to another
  (declining A as B rises), with overlap window and shared-link/username
  corroboration. Descriptive only — a migration is a temporal pattern, not proof
  the accounts are the same person.
