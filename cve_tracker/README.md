# cve_tracker — CVE Intelligence & Tracking

A defensive vulnerability-monitoring subsystem for the Sombra Guardian Telegram
bot. It watches public CVE sources, normalizes and de-duplicates the records,
enriches them (CVSS / CWE / CPE / KEV / exploit-reference classification),
produces a **validated Thai summary** using the project's existing AI provider,
and publishes filtered alerts to Telegram subscribers.

It is built like the project's other subsystem packages (`group_soc/`,
`purple_range/`): self-contained, dormant by default, wired in through a plugin +
a migration + one small `post_init` hook — **nothing here imports `app.py`.**

## Scope (what this is / is not)

This subsystem only **reads and reports** publicly disclosed vulnerability
information for defensive use: patch prioritization, vulnerability awareness,
blue-team intelligence, SOC monitoring. It classifies exploit *references* as
data and nothing more. It does **not** fetch, download, generate or execute
exploit code, and adds no offensive capability whatsoever.

## The pipeline

```
PUBLIC SOURCES (NVD · CVE.org · CISA KEV · GitHub Advisories · Vendor feeds)
        │  concurrent, rate-limited, retry+backoff, conditional requests
        ▼
SOURCE ADAPTERS ──▶ INGESTION (normalize → validate → dedupe/merge → enrich)
        ▼
ENRICHMENT (CVSS v2/3/3.1/4 · CWE · CPE · KEV · exploit refs · timeline)
        ▼
INTELLIGENCE (internal priority signal · change detection · correlation)
        ▼
AI LAYER (structured facts → Thai summary → hallucination validation → fallback)
        ▼
ALERTS (subscription filter → route → throttle/flood-control → Telegram)
```

## Quick start

1. Run migrations (the platform does this at startup; `migrations/m0008_cve_tracker.py`).
2. Set at least `CVE_TRACKER_ENABLED=true` in `.env`. Optionally add
   `CVE_NVD_API_KEY` and `CVE_GITHUB_TOKEN` for higher rate limits.
3. In a group, an admin runs `/cve_subscribe critical` (or `kev`, or
   `vendor microsoft`, …) to start receiving alerts.

Nothing is broadcast until a chat subscribes — the safe default is "collect,
don't broadcast".

## Commands

| Command | Who | Purpose |
|---|---|---|
| `/cve <ID>` / `/cve_info <ID>` | all | Show a CVE's details |
| `/cve_search <query>` | all | Search (`apache`, `severity:critical`, `vendor:cisco`, `cwe:CWE-79`, `kev`) |
| `/cve_recent` / `/cve_latest` | all | Newest CVEs |
| `/cve_kev` | all | CVEs in CISA KEV |
| `/cve_stats` | all | Statistics |
| `/cve_subscribe [filters]` | all | Configure this chat's alerts |
| `/cve_unsubscribe` / `/cve_preferences` | all | Manage this chat's alerts |
| `/cve_sources` | all | Per-source health |
| `/cve_status` | admin | Subsystem status |
| `/cve_sync` | admin | Manual sync |
| `/cve_test` | admin | Render a sample alert |

## Documentation

* `ARCHITECTURE.md` — module map and data flow
* `CONFIGURATION.md` — every environment variable
* `SOURCES.md` — the source adapters and how to add one
* `AI_PIPELINE.md` — prompt, validation and fallback
* `DATABASE.md` — schema, indexes, retention
* `OPERATIONS.md` — running, monitoring, troubleshooting
