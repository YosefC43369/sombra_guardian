# Changelog — Entity Fusion Engine

## v1.0.0

Initial release of the `entity_fusion/` identity-correlation subsystem.

### Added

**Core correlation (stdlib-only, fully tested)**
- Universal `Entity` model with provenance (`SourceRef`), append-only
  `Evidence`, typed `Relationship`, and auditable `merge`.
- Multilingual normalization: Unicode NFKC, homoglyph/confusable skeletons,
  emoji/zero-width/control stripping, and script-aware cleanup for
  Arabic/Hebrew/Thai/CJK. Type canonicalizers for email (Gmail dot/plus
  folding), username (separator/leet/variant), phone (E.164 + region), URL and
  domain (IDNA).
- Explainable multi-factor `SimilarityEngine` (Levenshtein, Jaro-Winkler, token
  Jaccard, n-gram cosine) with weighted, per-signal breakdown and hard-identifier
  short-circuit.
- Blocking + union-find `Clusterer`.
- Deterministic, explainable `ConfidenceEngine` (0–100, bands, positive/negative
  evidence, conflict detection).
- `Identity` aggregate and `FusionEngine` orchestrator; async, depth-bounded,
  cycle-safe `RecursivePipeline`.
- Relationship graph (`networkx`-optional) with GraphML / GEXF / JSON / DOT
  exports and optional GraphViz rendering.
- Temporal `HistoryEngine` (change events → timeline).

**Offline engines** — username, email, phone, crypto (BTC/ETH+EVM/Solana/
Litecoin/Tron/Monero format validation), domain, ip, asn, certificate, website,
organization. Plus bio email/wallet extractors.

**Network enrichers** (public sources, httpx-optional) — gravatar, github,
crt.sh, DNS-over-HTTPS, RDAP/whois, wayback, ipinfo, urlscan, AlienVault OTX.

**Storage & reports** — SQLite store (entities/aliases/relationships/evidence/
history/cache), memory + disk + tiered caches, async scheduler; JSON / Markdown /
CSV / HTML / GraphViz reports and a `bundle` export.

### Security posture
- **Fail-closed `FusionGate`** integrating `scope_policy`: infrastructure targets
  are scope-checked; person-level correlation requires an explicit
  `allow_person_scope` flag tied to an authorized program (off by default).
- Public data only; SSRF hygiene (non-global IPs dropped); no biometrics/facial
  recognition; no credential access or auth bypass. Consistent with the `osint/`
  package's documented scope line.

### Tests
- 186 tests, ~90% coverage. Pure stdlib; no network required.

### Known boundaries (v1)
- Avatar correlation operates on supplied `avatar_sha256`/`avatar_phash`
  metadata; the image download + perceptual-hash enricher (Pillow/imagehash) is
  a documented extension point, not shipped.
- Arbitrary-person breach/exposure lookups are intentionally not implemented.
- Telegram command handlers and direct platform-DB table creation are integration
  points documented for a follow-up; the engine exposes the façade
  (`FusionEngine`, `RecursivePipeline`, `reports`, `SQLiteStore`) they build on.
