# Web Footprint Intelligence Engine

Package: [`web_footprint/`](../web_footprint)

A passive attack-surface reconnaissance engine for authorized red-team
engagements, security assessments, OSINT investigations, and defensive asset
discovery. Given a seed target, it maps an organization's **publicly observable**
web footprint — domains, subdomains, websites, public APIs and documentation,
technologies, DNS and certificate intelligence, hosting and cloud references,
public documents and repositories, the developer footprint, and the historical
footprint — correlates it into an attack-surface graph, scores relevance, and
renders an evidence-backed report.

It answers one question:

> *What publicly observable digital infrastructure, websites, documents,
> technologies, domains, repositories, historical assets, and relationships can
> be mapped without actively attacking the target?*

## Posture — 80% red team / 20% blue team

The engine is primarily a deep **passive reconnaissance** capability for
authorized red-team work (its 80%): the pipeline, collectors, analyzers, graph,
scoring and the 22-section report all serve that goal. A deliberately smaller
**defensive companion** (`web_footprint.blue`) reuses the same passive output for
asset inventory, exposure-change monitoring, brand/impersonation detection, IOC
enrichment hand-off, and factual posture signals.

## Hard scope line (enforced in code)

This engine **stops at reconnaissance**. By construction it implements none of:

- exploitation, credential attacks, or authentication bypass;
- stealth, evasion, CAPTCHA bypass, or rate-limit bypass;
- private-account access, unauthorized scanning, or active probing.

Enforcement, not just documentation:

- **Fail-closed authorization.** `ReconGate` checks the seed against the
  repository's reviewed-authorization tables in `scope_policy` — the same
  machinery `/bbscan` and `entity_fusion` use. No program, no scope-policy, or
  any error ⇒ **DENY**, and no collector runs. A local `dev_unsafe_allow_all`
  flag exists for tests only and logs loudly.
- **Public sources only.** Every collector reads already-public data:
  Certificate Transparency (crt.sh), public DNS over DoH, the Wayback web
  archive, the target's own published `/.well-known` files, and public
  repository metadata.
- **Scope-aware.** Discovered assets are tagged `IN_SCOPE` / `OUT_OF_SCOPE` /
  `UNKNOWN` against the declared engagement scope. A bug-bounty program's
  existence never implies authorization.
- **Secret-safe.** Secret-like strings found in public text are **redacted and
  classified, never validated or used**.
- **Discovery ≠ ownership; naming ≠ exposure; version ≠ vulnerability.** Each
  is surfaced as an evidence-backed observation, never a claim.

## Architecture

Async- and stdlib-first, layered on the `osint` framework's HTTP backbone
(shared rate limiting, retry, request budget). `httpx` and `networkx` are
optional: the pure core (normalization, inventory, offline analyzers, graph,
scoring, history, reports) runs and is fully tested with zero third-party
dependencies; network collectors activate when `httpx` is present, and a
`networkx` export activates when `networkx` is.

```
web_footprint/
├── config.py            run modes (QUICK/STANDARD/DEEP) + pivot limits
├── normalize.py         canonicalize domains/URLs/emails, eTLD+1, containment
├── assets.py            Asset / AttackSurfaceInventory / Evidence / confidence
├── authorization.py     ReconGate (fail-closed) + ScopeSpec/ScopeClassifier
├── collectors/          passive public-source collectors
│   ├── certs.py           Certificate Transparency (crt.sh)
│   ├── passive_dns.py     public DNS over DoH
│   ├── archive.py         Wayback Machine (historical URLs/docs)
│   ├── wellknown.py       robots.txt / sitemap.xml / security.txt / root page
│   └── repos.py           public repository references (GitHub search)
├── analysis/            offline (no-network) analyzers
│   ├── subdomain_roles.py role classification by name (naming signal only)
│   ├── tech.py            technology + version fingerprinting
│   ├── extract.py         reference extraction + secret redaction
│   ├── security_signals.py security.txt / headers / bug-bounty / status
│   └── exposure.py        exposure categories + observed-surface metrics
├── graph.py             attack-surface graph + depth-bounded passive pivots
├── scoring.py           PassiveReconRelevanceScore (NOT a vuln score)
├── history.py           CURRENT-vs-HISTORICAL diff + technology timeline
├── pipeline.py          the passive recon pipeline (orchestration)
├── engine.py            WebFootprintEngine facade (async + sync)
├── blue/monitor.py      defensive 20%: inventory, alerts, brand, IOC hand-off
└── reports/             22-section red-team Markdown + machine JSON
```

## Pipeline

```
seed → AUTHORIZE (fail-closed) → run enabled COLLECTORS (passive, concurrent,
budget-bounded) → INGEST into inventory → offline ANALYZERS → CLASSIFY SCOPE →
ATTACK-SURFACE GRAPH → EXPOSURE analysis → RELEVANCE scoring → (DEEP) passive
PIVOTS → red-team REPORT.
```

Every ceiling in `ReconLimits` is honoured: collector concurrency, total request
budget, wall-clock cap, per-type asset caps, and pivot-depth ceiling — so
recursive pivoting can never fan out without bound.

## Run modes

| Mode | Adds |
|---|---|
| `QUICK` | domain / subdomain / website / technology / certificate / document / repository — a concise attack-surface sketch |
| `STANDARD` | + historical archives, DNS, document metadata, repository relationships, technology timeline, public API docs, graph construction |
| `DEEP` | + recursive passive pivots, cross-source correlation, certificate relationships, public-cloud signals, exposure analysis, change detection |

All three are passive; a mode only changes public-source breadth, never unlocks
an active probe.

## Quick start

```python
from web_footprint import WebFootprintEngine, ReconContext, ScopeSpec, ReconMode
from web_footprint.reports import red_team

engine = WebFootprintEngine()
ctx = ReconContext(
    program_id=7,                              # a reviewed scope_policy program
    scope=ScopeSpec(include=["*.example.com"]),
)
result = await engine.recon("example.com", ctx, mode=ReconMode.STANDARD)
print(red_team.render(result))                 # 22-section Markdown report
```

Blue-team use:

```python
from web_footprint.blue import BlueTeamMonitor

monitor = engine.monitor()
result = await monitor.run_snapshot("example.com", ctx)
inventory = BlueTeamMonitor.defensive_inventory(result)   # reconcile vs. your own
alerts    = BlueTeamMonitor.compare(result, previous_snapshot)  # exposure changes
lookalike = BlueTeamMonitor.brand_monitor("example.com", candidate_domains)
```

## Relevance scoring vs. exposure

- **`PassiveReconRelevanceScore` (0–100)** — how relevant and well-corroborated a
  discovered asset is (domain relevance, source quality, cross-source
  corroboration, historical consistency, technology/infrastructure evidence).
  It is **not** a vulnerability score.
- **Observed public surface** — factual metrics (counts of domains, subdomains,
  websites, documents, repositories, technologies, certificates, historical
  assets). The engine deliberately does **not** assign a "security maturity"
  grade from passive data.

## Reports

- `reports/red_team.render(result)` — the 22-section passive-recon report:
  Target, Scope, Executive Summary, Domain/Subdomain/Website inventories, Public
  API/Documentation, Technology Footprint, DNS/Certificate Intelligence,
  Hosting/Infrastructure, Public Documents/Repositories, Developer Footprint,
  Historical Footprint, Public Cloud Signals, Attack-Surface Graph, Passive
  Exposure Signals, Correlations, Evidence, Confidence, and a Limitations
  section that states plainly what passive recon did not and could not do.
- `reports/json_report.render(result)` — the full structured output.

## Testing

The engine is fully tested offline (no network, no `httpx`, no `scope_policy`
state) with injectable fake collectors:

```
python3 -m unittest discover -t . -s web_footprint/tests -p "test_*.py"
```

86 tests cover normalization, the inventory model, authorization (including the
fail-closed deny paths), every analyzer, the collectors' pure parsers, the
graph, scoring, history, the pipeline (gate/scope/caps/budget), the engine
facade, the blue-team monitor, and the reports.

## Dependencies

No new dependencies. Network collectors use the existing `httpx` (already in
`requirements.txt`) via the `osint` HTTP client; `networkx` is optional and only
enables a graph export.
