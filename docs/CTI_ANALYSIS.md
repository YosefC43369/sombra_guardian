# Cybersecurity Intelligence Analysis Engine (`cybersecurity_intelligence`)

The CTI Analysis Engine is the **analytic layer** of Sombra Guardian. It does not
collect news or re-implement the CTI knowledge base — that already lives in
[`threat_actor_intelligence`](../threat_actor_intelligence) (ingestion for
CISA/NVD/MITRE/OTX/URLhaus/MalwareBazaar/STIX/TAXII/RSS/vendor/GitHub, the
actor/campaign/malware/IOC/technique models, correlation, graph, timeline,
reports and SQLite storage) and in `blueteam` (IOC feeds, sightings, decay).

What this package adds is the discipline that turns collected public data into
**finished intelligence** — the difference between a news aggregator and an
intelligence platform:

```
public data → EVIDENCE → CLAIMS → CORROBORATION → CONTRADICTION → CONFIDENCE → ASSESSMENT → REPORT
```

Every conclusion is traceable back to the source(s) that produced it.

## Design guardrails (enforced in code)

- **Evidence first.** A non-`UNKNOWN` claim without at least one citation fails
  `Claim.validate()`.
- **Provenance everywhere.** Every claim carries an `EvidenceBundle` of
  `EvidenceRef`s (provider, source class, URL, external id, excerpt, TLP,
  observed/collected timestamps) — reused verbatim from
  `threat_actor_intelligence.models.evidence`.
- **Correlation before conclusion; confidence before assertion.** Confidence is
  computed in one place and is *explainable* (factor breakdown + limitations).
- **No single signal is attribution.** Shared IP / domain / name / country /
  certificate never promote a claim on their own; corroboration requires
  *independent* sources.

## The claim taxonomy

`ClaimType` is deliberately richer than the actor engine's `AssertionKind`:

| Claim type     | Meaning                                             | Confidence ceiling |
|----------------|-----------------------------------------------------|--------------------|
| `OBSERVED`     | the fact is directly present in a source            | 1.00 (evidence decides) |
| `CORROBORATED` | ≥ N *independent* sources assert it                 | 1.00 (evidence decides) |
| `REPORTED`     | a single source asserts it                          | 0.75 |
| `INFERRED`     | our analytic interpretation of evidence             | 0.60 |
| `DISPUTED`     | sources conflict on this claim                      | 0.45 |
| `UNKNOWN`      | public data cannot establish it                     | 0.25 |

Promotion is **earned**: `REPORTED → CORROBORATED` happens only when the evidence
clears the independent-source threshold; `DISPUTED` is set only when the
contradiction engine finds a conflict. The engine never silently promotes a
single-source report to a confirmed fact.

## Source independence — "20 copies ≠ 20 evidence"

`EvidenceEngine` groups citations before counting them:

- all pure **aggregators/feeds collapse into one "secondary pool"** — collectively
  at most one independent source;
- **primary citations are grouped by registrable host**, so two URLs on the same
  publisher count once.

The number of resulting groups is the *independent source count*, and only that
count drives corroboration. A wire story reprinted on twenty aggregator sites does
not manufacture corroboration.

## Contradiction — surfaced, never adjudicated

`ContradictionEngine` groups claims by `(subject, dimension)` — attribution,
exploitation status, severity, malware naming, target, infrastructure ownership,
timeline — and flags any subject on which ≥ 2 *distinct* values are asserted. Both
positions are recorded with their sources; the platform never picks a winner.

## Assessments separate FACT / SOURCE CLAIM / ANALYTIC INFERENCE / UNCERTAINTY

`AssessmentEngine` builds a structured `Assessment` where every line is typed by
epistemic register, so a reader can never mistake an inference for a source-reported
fact. It also derives an operational **priority** from *defensive* signals only
(exploitation reported, severity, known-ransomware association) — never from any
judgement about an actor's intent — and every priority carries its reason.

## Usage

```python
from cybersecurity_intelligence import CTIAnalysisEngine, CTIStore

engine = CTIAnalysisEngine(store=CTIStore("cybersecurity_intelligence.db"))

articles = [
    {"title": "...", "summary": "...", "source": "CISA",
     "source_class": "government", "url": "https://...", "published_at": "2021-12-11T00:00:00Z"},
    # ...
]

result = engine.analyze_articles(articles)          # transform→consolidate→contradict→score→persist
assessment = engine.assess("cve:cve-2021-44228")    # build a structured assessment
print(engine.render(assessment, result.contradictions, fmt="markdown"))
```

Run the pure in-memory pipeline (no persistence) by constructing the engine with
`store=None` and passing `persist=False`.

## Data model & storage

`CTIStore` (stdlib `sqlite3`, WAL, JSON-blob + indexed scalar columns, optional
FTS5 search) owns four `cti_`-prefixed tables — it does **not** duplicate the
actor/IOC tables owned by `threat_actor_intelligence`:

| Table                | Holds                                             |
|----------------------|---------------------------------------------------|
| `cti_sources`        | graded publishers (`SourceRecord` + reliability)  |
| `cti_claims`         | consolidated, scored claims                        |
| `cti_contradictions` | detected conflicts                                 |
| `cti_assessments`    | finished assessments                               |

Schema is registered centrally in
[`migrations/m0005_cti_analysis.py`](../migrations/m0005_cti_analysis.py)
(non-destructive, reversible) and self-initialized by the store for zero-config
startup — the repo's documented dual pattern.

## Configuration (`CTI_*`)

All knobs are read from the environment at call time via
`cybersecurity_intelligence.config.get_config()`. Every one has a safe default so
the analytic core runs with zero configuration.

| Env var | Default | Meaning |
|---------|---------|---------|
| `CTI_ENABLED` | `true` | master switch |
| `CTI_DB_PATH` | `cybersecurity_intelligence.db` | analytic store path |
| `CTI_REFRESH_INTERVAL` | `3600` | scheduler poll seconds |
| `CTI_MAX_CONCURRENCY` | `8` | ingestion concurrency ceiling |
| `CTI_REQUEST_TIMEOUT` | `20.0` | per-request timeout |
| `CTI_MAX_ARTICLE_SIZE` | `2000000` | per-article byte cap |
| `CTI_MAX_DOCUMENT_SIZE` | `10000000` | per-document byte cap |
| `CTI_MAX_RESULTS` | `500` | default paging cap |
| `CTI_RATE_LIMIT` | `60.0` | requests/min |
| `CTI_RETENTION_DAYS` | `365` | retention window |
| `CTI_ENABLE_ALERTS` | `false` | alert generation |
| `CTI_ENABLE_GRAPH` | `true` | graph features |
| `CTI_ENABLE_TREND_ANALYSIS` | `true` | trend features |
| `CTI_CORROBORATION_MIN_SOURCES` | `2` | independent sources for corroboration |

## Scope & safety

This is an **intelligence** platform, not an intrusion platform. It analyzes only
public reporting: it does not scan, exploit, generate payloads, or access private
data. Analytic language is calibrated (`reported` / `observed` / `corroborated` /
`disputed` / `unknown`), attribution is treated as a spectrum with confidence and
evidence class, and the standing CTI limitations (public-source-only; aliases are
not identity; absence of a signal is not absence of activity) ride along on every
confidence score from the upstream `confidence` module.

## Tests

```bash
python -m pytest cybersecurity_intelligence/tests -q
```

Covers models & round-tripping, source-reliability grading, independence &
corroboration (including aggregator collapse), the confidence ceiling,
contradiction detection, article transformation, storage/search, the migration,
and the end-to-end facade pipeline (including determinism).

## Phase status

Phase 1 (this module) delivers the analytic core end-to-end: transform → evidence
→ claims → corroboration → contradiction → confidence → assessment → report, with
persistence, migration and tests. Follow-on phases extend breadth — more provider
transforms, Telegram commands (`/cti`, `/analyze`, `/correlate`, `/assessment`,
`/intel_report`, …), the correlation graph views, trend/change detection and the
alert engine — reusing this core and `threat_actor_intelligence` rather than
duplicating them.
