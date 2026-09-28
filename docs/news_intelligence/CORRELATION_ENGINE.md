# Correlation & Clustering Engine

Correlation turns a corpus of stored articles into **explainable,
evidence-backed** relationships. Nothing is asserted as fact: a correlation says
"these co-occur in public reporting", never "X did Y". Every output records the
shared signals, the supporting article ids, the independent source count, and a
computed `ConfidenceModel`.

## Confidence discipline

All scoring goes through `news_confidence(bundle, now=...)`, which reuses the CTI
engine's noisy-OR corroboration across **distinct providers**, recency decay and
sample saturation, then folds on both the shared and the news-specific standing
limitations. Confidence means **evidence quality**, never certainty of a claim.
Crucially, corroboration counts distinct originating domains only — ten copies of
one wire story count once.

## Correlators

| Correlator | Answers |
|---|---|
| `EntityCorrelator` | which actors/malware/CVEs/countries co-occur (actor_uses_malware, malware_exploits_cve, …) |
| `ArticleCorrelator` | which articles corroborate / relate to each other (typed shared-signal scoring) |
| `InfrastructureCorrelator` | which IOCs appear across unrelated sources (cross-source infrastructure) |
| `ReportCorrelator` | source corroboration: original vs independent vs syndicated vs mirror vs research-summary |
| `CampaignCorrelator` | campaign → actor/malware/CVE links, preserving independent sources |
| `TopicCorrelator` | topic co-occurrence + vendor comparison for a subject |

### Shared-signal weighting (article correlation)

Typed signals outrank shared common words: `cve`/`ioc` = 1.0, `actor`/`malware` =
0.9, `technique` = 0.7, `org` = 0.5, `country` = 0.3. Two articles linked by a
shared CVE and IOC across two different outlets become a `corroborates` edge; the
same signals within one outlet become `related`.

## Clustering

| Clusterer | Purpose | Signals |
|---|---|---|
| `DuplicateDetector` | duplicate / near-duplicate detection | canonical URL → SHA256 → SimHash Hamming → MinHash Jaccard → TF-IDF cosine |
| `EventClusterer` | multiple articles → one event | shared CVE/malware/actor/org/IOC + publication window + semantic similarity |
| `TopicClusterer` | thematic topics over time | salient shared entities / keyword document-frequency |
| `CampaignClusterer` | merge reports about one campaign | explicit campaign name, else (actor+malware+CVE) fingerprint |

Every cluster records **why** its members are together (`signals`), so the grouping
is auditable. The duplicate detector picks the original (earliest published, most
reliable source) and stamps `duplicate_of` on the copies; downstream counts and
corroboration exclude duplicates.

## Source corroboration roles

`ReportCorrelator` classifies each contributing article: `original`,
`independent`, `syndicated` (marked duplicate), `mirror` (same domain), or
`research_summary` (a later write-up). Only distinct independent domains raise the
corroboration score.

## Contradictions

`CampaignClusterer` records **differing claims** (e.g. two outlets attributing the
same campaign to different actors) as `DifferingClaim` rows. The engine **never
auto-resolves** a contradiction — both claims are stored with their sources and
shown side by side in the campaign report.

## Example

```python
from news_intelligence.correlation.infrastructure_correlation import InfrastructureCorrelator
xs = InfrastructureCorrelator(store).cross_source_iocs(articles, min_domains=2)
# → [{"value": "evil.com", "independent_sources": 3, "articles": [...], "confidence": {...}}]
```
