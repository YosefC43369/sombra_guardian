# Similarity Model

`entity_fusion/similarity.py` answers two questions: how similar are two strings,
and how strongly does the evidence say two entities are the same real-world
thing. Every entity comparison is **explainable** — the result carries each
contributing signal, its raw value and its weight.

## String primitives (all pure stdlib)

| Function | Use |
| --- | --- |
| `levenshtein` / `levenshtein_ratio` | Edit distance → [0,1] similarity. Domains, generic strings. |
| `jaro` / `jaro_winkler` | Short-string similarity with shared-prefix boost. Usernames, names. |
| `token_jaccard` | Order-independent word-set overlap. Multi-word names/orgs. |
| `ngram_cosine` | Character n-gram cosine. Longer text (bios), typo-robust. |
| `jaccard` | Set overlap for collections (hashtags, shared links). |
| `best_name_similarity` | Blends JW / token-Jaccard / n-gram for display names. |

## Multi-factor entity scoring

`SimilarityEngine.score_entities(a, b) → SimilarityResult`

### Signals and default weights

| Signal | Weight | Notes |
| --- | ---: | --- |
| `email` | 5.0 | also a hard identifier |
| `phone` | 5.0 | also a hard identifier |
| `avatar_hash` | 5.0 | also a hard identifier |
| `wallet` | 6.0 | also a hard identifier |
| `certificate` | 6.0 | also a hard identifier |
| `username` | 4.0 | |
| `display_name` | 3.0 | |
| `website` | 3.0 | |
| `organization` | 2.5 | |
| `shared_links` | 2.5 | |
| `bio` | 2.0 | |
| `username_core` / `dns_record` | 2.0 | |
| `email_domain` / `hashtags` | 1.5 | |
| `timezone` / `language` | 1.0 | |

Weights are injectable: `SimilarityEngine(weights={...})`.

### Hard identifiers

A byte-identical `avatar_sha256`, `avatar_phash`, `wallet`,
`certificate_fingerprint`, `pgp_fingerprint`, or an identical normalized primary
value for a wallet/certificate entity, is treated as **near-conclusive**. When a
hard identifier matches, the score is promoted to at least `hard_match_floor`
(default 0.97) — but never a fabricated 1.0, leaving headroom the confidence
engine can erode with contradictions.

### Combining

- Soft signals combine as a weighted mean and are **capped at 0.95** — soft
  evidence alone never asserts identity.
- The `SimilarityResult` exposes `.percent`, `.explanation()` (human string) and
  `.to_dict()` (per-signal breakdown) so the number is always auditable.

```python
res = SimilarityEngine().score_entities(a, b)
print(res.explanation())
# score=100.0% [HARD MATCH] :: primary_value=1.00(w6.0), display_name=1.00(w3.0)
```
