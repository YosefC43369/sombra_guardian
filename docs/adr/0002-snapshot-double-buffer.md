# ADR 0002 — Double-buffer (copy-on-write) snapshots for the IOC lookup index

**Status:** accepted (v0.8.0) · **Context:** Threat-Intel lookup engine

## Context
The IOC index (exact sets, reverse-label domain trie, sorted CIDR ranges, Bloom
filter) is read on the hot message path and rebuilt whenever a feed sync ingests
new IOCs. Readers and the rebuild can overlap. Locking every lookup would add
contention to the hottest path; mutating the live structures in place risks a
reader seeing a half-built index.

## Decision
Build a fresh, **immutable** `Snapshot` off to the side and swap a single reference
(`LookupEngine.swap`). Under CPython a plain attribute assignment is atomic, so a
lookup either sees the whole old snapshot or the whole new one — never a mix — with
**no lock on the read path**. Each `lookup` reads `self._snap` once into a local.

## Consequences
- Lock-free, allocation-free reads; refresh cost is paid by the writer.
- Correctness verified against a brute-force reference (trie/CIDR) with a fixed seed.
- The LRU cache is cleared on swap so it can't serve stale results.
- Trade-off: transient 2× memory during a rebuild (old + new snapshot). Acceptable —
  the index is bounded by config (`bloom_capacity`, feed caps) and a rebuild is brief.
- Alternative rejected: `RWLock`/`copy.deepcopy` per read — more code, slower reads,
  and still needs a consistent view. The reference swap gives the consistent view for free.
