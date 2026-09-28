# Changelog — Web Footprint Intelligence Engine

## v1.0.0

Initial release of the `web_footprint/` passive attack-surface reconnaissance
subsystem, configured 80% red-team / 20% blue-team.

### Added

**Core (stdlib-only, fully tested)**
- `AttackSurfaceInventory` + `Asset` model with append-only `Evidence`,
  source-quality-weighted, corroboration-based `confidence` (0–100, banded),
  and key-based de-duplication/merge. Asset, domain-class, subdomain-role,
  signal-state and exposure-category taxonomies.
- `normalize` — canonical domains/URLs/emails/usernames, best-effort eTLD+1
  (registrable domain), host containment, and label splitting; reuses the
  repo's strict, SSRF-aware `osint` validators.
- `config` — `ReconMode` (QUICK/STANDARD/DEEP), per-mode stage matrix, and
  `ReconLimits` (pivot depth, max domains/subdomains/documents/repositories/
  URLs, request budget, runtime cap, concurrency, rate).
- Attack-surface `graph` (`networkx`-optional, pure fallback) with passive edge
  kinds and a depth-bounded pivot walk; DOT/JSON export.
- `PassiveReconRelevanceScore` — explainable, deterministic 0–100 relevance
  (domain/asset/source-quality/corroboration/historical/technology/
  infrastructure factors). Explicitly **not** a vulnerability score.
- `history` — snapshotting, CURRENT-vs-HISTORICAL diff
  (ADDED/REMOVED/CHANGED/REAPPEARED/UNCHANGED), and technology timeline.

**Passive collectors** (public sources, `httpx`-optional via the `osint` HTTP
backbone) — Certificate Transparency (crt.sh), public DNS over DoH, the Wayback
Machine (historical URLs/documents), the target's own `/.well-known` files
(robots.txt, sitemap.xml, security.txt, root page), and public repository
references (GitHub search; key-optional, degrades to `AUTH_REQUIRED`).

**Offline analyzers** (pure, no network) — subdomain-role classification (naming
signal only), technology + version fingerprinting (headers/cookies/HTML/meta),
reference extraction (domains/subdomains/IPs/emails/URLs/cloud/API/package/
CI-CD/internal-naming) with secret **redaction**, passive security signals
(security.txt, security headers, bug-bounty/disclosure, status page), and
exposure classification + observed-public-surface metrics.

**Facade, reports & blue team** — `WebFootprintEngine` (async + sync,
quick/standard/deep) over the `ReconPipeline`; a 22-section red-team Markdown
report and a machine JSON report; and `BlueTeamMonitor` (defensive inventory,
exposure-change alerts, brand/impersonation look-alike detection, IOC enrichment
hand-off, factual posture signals).

### Security posture
- **Fail-closed `ReconGate`** integrating `scope_policy`: the seed target is
  scope-checked against a reviewed, effective authorization before any collector
  runs; no program / no scope-policy / any error ⇒ DENY. A `dev_unsafe_allow_all`
  flag exists for local tests only and logs loudly.
- **Passive and public-only** by construction: no exploitation, credential
  attacks, auth bypass, stealth/evasion, CAPTCHA/rate-limit bypass, private
  access, or active scanning. Consistent with the `osint/` and `entity_fusion/`
  scope lines.
- Scope-aware asset tagging (IN/OUT/UNKNOWN); a bug-bounty program is never
  treated as authorization. Secret-like strings are redacted, classified, and
  never validated or used. Discovery ≠ ownership; naming ≠ exposure; version ≠
  vulnerability.

### Tests
- 86 tests. Pure stdlib; no network, `httpx`, `networkx`, or `scope_policy`
  state required. Fake collectors exercise the full pipeline offline, including
  the fail-closed deny paths and the secret-redaction guarantee.

### Known boundaries (v1)
- Deep code intelligence (extracting endpoints/config from repository *contents*)
  is performed offline by `analysis.extract` on any supplied text; repository
  content fetching beyond metadata is a documented extension point via the
  existing `github_repo` module.
- Document *metadata* extraction (PDF/Office authorship, producer) is a
  documented extension point; the engine ingests document URLs and routes any
  supplied text through the reference/secret analyzers.
- Telegram command handlers are an integration point for a follow-up; the engine
  exposes the façade (`WebFootprintEngine`, `ReconPipeline`, `reports`,
  `BlueTeamMonitor`) they build on.
