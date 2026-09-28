# Entity Extraction

The extraction layer (`news_intelligence/extraction/`) turns article text into a
deduplicated list of typed, normalized `EntityMention` objects. Every extractor is
**pure** (no I/O) and unit-tested offline, and indicator parsing is delegated to
the Threat Actor Intelligence Engine's proven miner so the two engines canonicalize
IOCs identically (spec: *avoid duplicate extraction logic*).

## Entity types

Threat actor, campaign, malware family, organization, company, government agency,
country, city, domain, IP, ASN, URL, email, repository, CVE, CWE, CAPEC, ATT&CK
technique, software, cloud provider, product, hash.

## `EntityMention`

| Field | Meaning |
|---|---|
| `entity_type` | typed enum |
| `value` | **normalized** form (`APT 29` → `APT29`, `EVIL[.]COM` → `evil.com`) |
| `surface` | exactly as written in the source (provenance) |
| `start`/`end` | char span in the source text (or -1) |
| `extractor` | which extractor produced it |
| `weight` | extractor confidence (0..1) |
| `context` | short surrounding span |
| `entity_key` | stable id per `(type, value)` — the graph node identity |

A mention **never asserts identity**: an `APT29` mention and a `Cozy Bear` mention
are two mentions until an evidence-backed alias link says otherwise.

## Extractors

| Extractor | Produces | Method |
|---|---|---|
| `IOCExtractor` | domain/IP/URL/email/hash/ASN | CTI miner (fallback stdlib), defang-aware |
| `URLExtractor` | URL + repository | github/gitlab/bitbucket refs |
| `CVEExtractor` | CVE/CWE/CAPEC | flags `exploit_context` / `patch_context` from surrounding words |
| `MitreExtractor` | ATT&CK technique | Txxxx ids + technique-name resolution via the CTI ATT&CK KB |
| `ActorExtractor` | threat actor | dictionary (alias clusters) + designators (APT##/UNC####/TA###) + codenames near cue words |
| `MalwareExtractor` | malware family | dictionary + codenames near malware cue words |
| `OrganizationExtractor` | org / company / agency / cloud | dictionary + corporate-suffix pattern |
| `LocationExtractor` | country / city | country + demonym dictionary; airport dataset cities when present |

The composite `EntityExtractor` runs them all and `dedupe_mentions` collapses
duplicates by `entity_key`, summing occurrence counts and keeping the highest
extractor weight.

## Alias preservation

`extraction/reference.py` holds curated, **public** alias clusters (MITRE ATT&CK +
vendor naming): e.g. `APT29 = {Cozy Bear, Midnight Blizzard, Nobelium, UNC2452,
…}`. When any reported name matches, the mention records the canonical name in
`detail['canonical']` **and** the mention is emitted under its own value — so every
vendor alias is tracked separately and never silently merged into one identity.
The reader (and the correlation layer's evidence-gated alias links) decide identity,
not extraction.

## Precision over recall

Name extraction is deliberately high-precision: structured designators and
dictionary hits are trusted; free codenames are only proposed when adjacent to cue
words ("… group", "… ransomware") and are given a lower weight. A false actor name
is worse than a missed one.

## Example

```python
from news_intelligence.extraction import EntityExtractor
ms = EntityExtractor().extract(
    "Midnight Blizzard (APT29) exploited CVE-2024-1234 with Cobalt Strike; IOC evil[.]com")
# → THREAT_ACTOR APT29, THREAT_ACTOR "Midnight Blizzard" (canonical=APT29),
#   CVE CVE-2024-1234, MALWARE_FAMILY "Cobalt Strike", DOMAIN evil.com
```
