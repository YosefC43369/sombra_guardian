# Sources

All sources implement `CVESource` (`sources/base.py`) and are registered in
`sources/registry.py`. A source fetches incrementally through the shared
rate-limited `HttpFetcher`, parses its native shape into single-source
`CVERecord`s, and returns a `SourceFetchResult` with updated cursor/health. A
source **never raises on ordinary failure** — it returns `ok=False` so one
source failing can't stop the others.

## Built-in sources

### NVD (`nvd`) — primary, richest
NIST NVD CVE API 2.0. Carries CVSS (v2/v3.0/v3.1/v4.0), CWE weaknesses, CPE
configurations with version ranges, tagged references, and reliable
published/lastModified timestamps. Incremental via `lastModStartDate` /
`lastModEndDate` windows (≤ 120 days) with `startIndex` paging. Sends `apiKey`
when configured. **Trust weight: 90.**

### CVE.org (`cve_org`)
MITRE CVE Services (CVE Record Format 5.x) at `cveawg.mitre.org`. Decodes the
`containers.cna`/`adp` tree: descriptions, metrics, problemTypes (CWE),
affected (vendor/product/versions), references. Time-filtered listing.
**Trust weight: 80.**

### CISA KEV (`cisa_kev`)
The Known Exploited Vulnerabilities catalogue — one JSON document, fetched with
conditional requests (ETag/Last-Modified) so it is only reprocessed when it
changes. Each entry becomes a minimal record carrying `KEVInfo`; the merge folds
that authoritative "exploited in the wild" fact onto the full record.
**Trust weight: 95 (for KEV presence only).**

### GitHub Security Advisories (`github_advisory`)
Reviewed GHSA advisories at `/advisories`, mapped to CVE ids where present.
Needs a token for a usable rate limit, so it is **enabled only when
`CVE_GITHUB_TOKEN`/`GITHUB_TOKEN` is set**. Parses CVSS (v3.1 + v4), CWEs,
affected packages/ranges, references. A GHSA with no CVE is kept under its GHSA
key as an alias-only record so it can merge onto a CVE that arrives later.
**Trust weight: 70.**

### Vendor Advisories (`vendor_advisory`) — extensible skeleton
Reads operator-configured RSS/Atom feeds (`CVE_VENDOR_FEEDS=name=url,…`), scans
each entry for CVE ids, and attaches the vendor advisory URL as a reference.
Disabled by default. **Trust weight: 85.**

## Fetch discipline (rule §5)

* Rate limiting: a per-source async **token bucket** paces requests; a
  `Retry-After` on a 429 pauses the whole source.
* Conditional requests: ETag / Last-Modified are stored and replayed; a `304`
  is a cheap "nothing changed".
* Retries: exponential backoff **with full jitter** on 5xx/429/timeout/connection
  errors; permanent 4xx are not retried.
* Size ceiling: responses are streamed with a hard byte cap
  (`CVE_MAX_RESPONSE_BYTES`) — a decompression-bomb / memory-exhaustion guard.
* The subsystem never fetches a URL found *inside* a CVE record; only the fixed
  source API bases are fetched. `utils/urls.is_safe_public_url` rejects
  private/loopback targets for the one opt-in case (a configured vendor feed).

## Adding a source

1. Subclass `CVESource`, set `name`/`kind`, implement `async fetch(ctx)`.
2. Register it in `sources/registry.default_registry()` (one line).
3. Add its `SourceConfig` defaults in `config.get_config()` (or rely on the
   generic `CVE_<NAME>_*` env keys).
4. No engine code changes — the registry and coordinator pick it up.
