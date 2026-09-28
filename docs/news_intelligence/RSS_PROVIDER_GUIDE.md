# RSS / Feed Provider Guide

The News Intelligence Engine collects from public feeds through a small set of
ingestors and a provider registry that maps each source category to the right
ingestor.

## Ingestors

| Ingestor | Provider name | Input | Notes |
|---|---|---|---|
| `RSSIngestor` | `rss` | RSS 2.0 / RDF | base feed parser |
| `AtomIngestor` | `atom` | Atom 1.0 | reuses RSS normalization |
| `JSONFeedIngestor` | `json_feed` | JSON Feed 1.x | jsonfeed.org |
| `VendorIngestor` | `vendor` | vendor blog RSS | optional full-page enrichment (readability + schema.org) |
| `CISAIngestor` | `cisa` | CISA advisory RSS | government evidence weight |
| `CISAKEVIngestor` | `cisa_kev` | KEV catalog JSON | marks publicly-confirmed exploited CVEs |
| `CERTIngestor` | `cert` | national CERT RSS | carries country |
| `NVDIngestor` | `nvd` | NVD CVE 2.0 API JSON | quotes CVSS verbatim, never re-scores |
| `GitHubBlogIngestor` | `github` | advisories atom / REST | GHSA + CVE mapping |
| `ExploitBlogIngestor` | `exploit_blog` | research RSS | discussion only, never exploit code |
| `PodcastIngestor` | `podcast` | podcast RSS | show-notes text, audio discarded |

Every ingestor separates a **pure** `parse(raw, ...)` (unit-tested offline against
fixtures) from an I/O `run(...)` that performs the polite conditional fetch.

## The polite HTTP layer

- conditional requests via stored `ETag` / `Last-Modified` (incremental — a feed
  that returns `304 Not Modified` is skipped);
- per-provider rate limiting (`RateLimiter`, configurable per provider);
- the configured `NI_USER_AGENT`;
- `httpx` when installed, stdlib `urllib` fallback otherwise.

Nothing here authenticates to a private/paywalled resource, bypasses auth, or
ignores rate limits.

## Source registry

A `NewsSource` records `name`, `category`, `reliability_class`, `country`,
`language`, `rss_url`, `website`, `update_frequency`, `enabled` and
`last_ingested`. Categories:

`vendor_security_blog`, `cert`, `government_advisory`, `threat_intel_vendor`,
`research_blog`, `open_source_project`, `news_organization`,
`cybersecurity_podcast`, `github_security_feed`, `public_stix_feed`.

`configuration.default_sources()` ships a curated registry of well-known public
feeds (CISA, NCSC, Unit 42, Talos, Mandiant, Securelist, The Hacker News,
BleepingComputer, GitHub advisories, SANS ISC, …). Extend it with
`NI_EXTRA_FEEDS` or by saving your own `NewsSource` rows.

## Adding a source

```python
from news_intelligence.models.source import NewsSource, SourceCategory, ReliabilityClass
src = NewsSource(name="Acme Labs", category=SourceCategory.VENDOR_SECURITY_BLOG,
                 reliability_class=ReliabilityClass.VENDOR_RESEARCH,
                 rss_url="https://labs.acme.example/feed/")
engine.store.save_source(src)
```

The scheduler will create a `Feed` for it on the next tick and poll it on its
`update_frequency` with failure backoff.

## Scheduling

`Scheduler.run_due()` polls only feeds whose interval (plus quadratic
failure-backoff) has elapsed, records per-feed success/failure, and hands the
collected articles to the orchestrator. Drive it on any cadence from `app.py`'s
job loop or external cron; it keeps all state in the store, so it survives
restarts.

## Reliability weighting

`reliability_class` (Admiralty-style) and `category` only **weight evidence
quality** — they never suppress collection and never assert a claim is true. The
weights feed the shared `ConfidenceModel` so a government advisory corroborated by
two independent vendors scores higher than a single anonymous blog.
