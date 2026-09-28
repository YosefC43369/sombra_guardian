# Campaign Engine

Package: `threat_actor_intelligence/models/campaign.py`,
`correlation/campaign_correlation.py`, `timeline/campaign_timeline.py`,
`graph/campaign_graph.py`, `reports/campaign_report.py`

Campaigns are modelled **separately** from actors on purpose: public reporting
often describes a bounded set of activity (shared TTPs / infrastructure / timing)
before, or without, confident attribution to a named actor. Keeping them distinct
lets the engine hold "campaign X used malware Y against sector Z" firmly while the
actor link stays an explicit, evidence-graded relationship that can be absent or
low-confidence.

## Model

`models.campaign.Campaign` fields: `campaign_id` (stable slug), `campaign_name`,
`aliases`, `summary`, `first_observed`, `last_observed`, `actors`,
`malware_families`, `infrastructure`, `iocs`, `techniques`, `victimology`,
`attack_campaign_id`, `references`, `report_ids`, `evidence`, `confidence`.

Helpers: `duration_days()`, `touch(when)`, `recompute_confidence(now)`,
`add_alias()`, `link(field, value)` (idempotent), lossless `to_dict`/`from_dict`.

## Correlation

`CampaignCorrelator` links campaigns by shared malware families, shared
infrastructure, shared IOCs, shared attributed actors and overlapping techniques,
and rewards **temporal overlap** (campaigns active in the same window). Hard
signals (shared infra/IOC/malware) weigh far more than a technique-only
co-occurrence; a single shared strong attribute already crosses the link
threshold (`count_multiplier`), while ≥3 shared items reach full weight.

```python
res = CampaignCorrelator().correlate(campaigns, now=now)
# Relationship(rel_type="overlaps", signal="infrastructure: infra-x; temporal overlap")
```

## Timeline

`CampaignTimelineBuilder` builds the dated chronology: first/last observed, each
corroborating report's publication, and dated IOC first-seen markers. Every event
requires a timestamp sourced from evidence (see the timeline design in
`THREAT_ACTOR_ENGINE.md`).

## Graph

`CampaignGraphBuilder` wires the campaign to its actors, malware, infrastructure,
IOCs, techniques and targeted victims (country/industry), exportable as
GraphML/GEXF/JSON/DOT.

## Report / dossier

`CampaignReportBuilder.build(campaign_id)` assembles the evidence-graded dossier:
executive summary, overview, attributed actors, malware relationships, ATT&CK
coverage, infrastructure, IOCs, victimology, corroborating reports, evidence,
confidence and limitations. Render with `render_report(dossier, fmt=...)`.

## Corroboration

"Which independent sources corroborate this campaign?" is answered by
`ReportCorrelator.corroborations(reports)` — an entity referenced by ≥2 distinct
sources is flagged corroborated, which also lifts its confidence.
