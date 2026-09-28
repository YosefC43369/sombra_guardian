# IOC Engine

Package: `threat_actor_intelligence/models/ioc.py`,
`correlation/ioc_correlation.py`, `ingestion/extract.py`

Normalizes publicly-reported indicators of compromise to a deterministic
canonical form so the same indicator reported by two vendors deduplicates to one
row, and correlates IOCs **only through documented public evidence**.

## Supported IOC types

`domain`, `url`, `ip`, `cidr`, `asn`, `md5`, `sha1`, `sha256`, `sha512`,
`email`, `cert_fingerprint`, `mutex`, `registry` (metadata), `yara_ref`
(rule name/reference), `sigma_ref` (rule title/reference), `filename`,
`user_agent`.

> YARA/Sigma are stored as **rule references only** — names/titles, never rule
> bodies. No sample bytes, no payloads (spec SECURITY BOUNDARIES).

## Canonicalization

```python
from threat_actor_intelligence.models import canonicalize, detect_type, IOCType, IOC
detect_type("hxxps://evil[.]com/x")          # IOCType.URL  (defanged input)
canonicalize(IOCType.DOMAIN, "Evil.Example.COM")  # "evil.example.com"
IOC.parse("AS13335")                          # IOCType.ASN -> "AS13335"
```

- Defanged input (`hxxp`, `[.]`, `(dot)`, `[at]`) is re-fanged before parsing.
- Domains are IDNA-encoded and validated; invalid values raise
  `CanonicalizeError` (they are dropped, never stored malformed).
- Hashes are validated by length/charset; IPs/CIDRs via `ipaddress`; ASNs
  normalized to `AS<n>`.
- The canonical `IOC.id = sha256(type|value)[:32]` gives idempotent dedup.
- `IOC.defanged()` renders a safe display form (shares `blueteam.urlkit.defang`
  when available).

## Text extraction

`ingestion/extract.extract(text)` mines defanged and plain indicators, CVE ids,
ATT&CK technique ids, and conservative actor/malware name candidates from free
text. It skips a curated false-positive domain list (documentation/reference
hosts). Name mining is deliberately high-precision (APT##/UNC####/TA### patterns
and capitalized codenames adjacent to cue words like "group", "campaign",
"backdoor").

## Correlation (evidence-gated)

`correlation.ioc_correlation.IOCCorrelator` links two IOCs only when they
co-occur under one of the documented signals:

- shared **campaign**, shared **malware**, shared **actor**;
- shared **report** (same external id / source url in evidence);
- shared **ASN** / **certificate** (from tags).

Each link is an explainable `Relationship(rel_type=associated_with)` whose
`signal` names the shared attributes and whose confidence is computed from the
union of the two IOCs' evidence. It never infers a link from value similarity
alone — being on the same /24 is only a signal when a source placed them
together or infrastructure correlation established the overlap.

```python
from threat_actor_intelligence.correlation import IOCCorrelator
res = IOCCorrelator().correlate(iocs, now=now)
res.relationships          # [Relationship(signal="shared campaign", ...)]
IOCCorrelator().group_by_signal(iocs)   # {signal: {value: [ioc_id, ...]}}
```

## Lookup

```python
engine.lookup_ioc("evil.example.com")
# {"ioc": {...}, "relationships": [...]}  or None
```

## Storage

IOCs live in the `ioc` table (indexed by value + type); evidence rows link into
the shared `evidence` table by `(object_type='ioc', object_id=ioc_id)`. Batch
writes go through `store.save_iocs(list)` in one transaction. See
`DATABASE_SCHEMA.md`.
