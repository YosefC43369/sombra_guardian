# Topic & Content Engine

Module: `behavioral_intelligence/content/`. Describes public content — topics,
URLs, domains, media, conversation structure and content reuse — with
first/last-seen provenance over an explicit window. No psychological or
ideological interpretation is attached; a topic is a group of words that appear
together.

## Topics (`topic_engine.py`, `topic_evolution.py`)

- `discover_topics` — no LDA/embedding dependency. Builds a co-occurrence graph
  over the top TF-IDF terms and extracts connected components as topic clusters,
  each labelled by its highest-weight term. Deterministic and explainable.
- `analyze_evolution` (§15) — slices the stream into periods (month/week),
  computes each period's salient terms, and reports which **emerged** in the
  latest period and which **faded**.

## URLs & domains (`url_behavior.py`, `domain_behavior.py`, §16–17)

- URL normalisation strips tracking params (utm_*, fbclid, …), lower-cases the
  host, drops fragments; coarse categorisation (code/social/video/paste/…).
- Domain aggregation with an eTLD-folding heuristic (`example.co.uk`), shortener
  detection, and window-to-window **transitions** (appeared / disappeared /
  retained). Strictly passive — nothing is resolved or fetched.

## Content reuse (`content_reuse.py`, §18–19)

Four methods, all stdlib:

| method | measure |
|--------|---------|
| `exact` | SHA-256 of normalised text |
| `simhash` | 64-bit LSH fingerprint, Hamming similarity |
| `minhash` | k-permutation MinHash, Jaccard estimate |
| `cosine` | TF-vector cosine |

Pairwise comparison is blocked by SimHash bucket to stay sub-quadratic on large
inputs. `repost_engine` classifies original/reply/repost/quote and detects
cross-posts (same content hash across ≥2 platforms). `thread_engine`
reconstructs threads and conversation depth from `thread_id`/`in_reply_to`,
truncating chains where intermediate posts weren't observed rather than
hallucinating structure.

## Entity extraction (`entity_extractor.py`)

Regex extraction of URLs, emails, @handles, #hashtags, IPv4/IPv6, and crypto
wallet addresses from public text, feeding the interaction graph and IOC
correlation.
