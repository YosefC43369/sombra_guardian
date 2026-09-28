"""
blueteam/intel/lookup.py — high-performance, read-only IOC lookup (pure; stdlib).

Design goals (spec D7):
  * O(1)-ish exact match for hashes / emails / t.me handles / wallets / exact URLs.
  * domain match that also catches subdomains, via a **reverse-label trie**
    (insert ``evil.com`` -> matches ``evil.com`` and ``login.evil.com``).
  * IP-in-CIDR via **sorted integer ranges + bisect** over ``ipaddress`` ints
    (separate v4/v6 arrays), O(log n).
  * a **Bloom filter** negative fast path so a clean message pays one hash and
    returns immediately without touching the exact structures.
  * a bounded **LRU** so hot values skip work entirely.
  * **double-buffer / copy-on-write snapshots**: a refresh builds a fresh
    immutable :class:`Snapshot` off to the side and swaps a single reference, so
    concurrent lookups never see a half-built index and never block on a lock.

Everything here is pure and offline; the service layer feeds it :class:`IOC`
objects and calls :meth:`LookupEngine.swap`.
"""

from __future__ import annotations

import bisect
import ipaddress
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .bloom import BloomFilter
from .domain import IOC, IOCType, canonicalize, detect_type

# IOC types matched by exact string equality.
_EXACT_TYPES = (
    IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.EMAIL,
    IOCType.TME_HANDLE, IOCType.WALLET, IOCType.URL, IOCType.IP,
)


@dataclass(frozen=True)
class MatchResult:
    ioc_id: str
    ioc_type: IOCType
    matched_value: str          # the stored IOC that matched (canonical)
    query_value: str            # what was looked up (canonical)
    reason: str                 # exact | domain_suffix | cidr
    confidence: int
    severity: str
    sources: Tuple[str, ...]


class _TrieNode:
    __slots__ = ("children", "ioc_id")

    def __init__(self):
        self.children: Dict[str, "_TrieNode"] = {}
        self.ioc_id: Optional[str] = None


@dataclass
class Snapshot:
    """An immutable index built once and swapped atomically."""

    exact: Dict[str, str] = field(default_factory=dict)          # canonical value -> ioc_id
    domain_root: _TrieNode = field(default_factory=_TrieNode)     # reverse-label trie
    v4_starts: List[int] = field(default_factory=list)
    v4_ranges: List[Tuple[int, int, str]] = field(default_factory=list)  # (start,end,ioc_id)
    v6_starts: List[int] = field(default_factory=list)
    v6_ranges: List[Tuple[int, int, str]] = field(default_factory=list)
    bloom: Optional[BloomFilter] = None
    iocs: Dict[str, IOC] = field(default_factory=dict)            # ioc_id -> IOC
    built_at: float = 0.0

    @property
    def size(self) -> int:
        return len(self.iocs)


def build_snapshot(iocs: List[IOC], *, now: float = 0.0,
                   bloom_error_rate: float = 0.001) -> Snapshot:
    """Build an immutable index from IOCs (expired ones skipped). Deterministic."""
    snap = Snapshot(built_at=now)
    exact_values: List[str] = []
    v4: List[Tuple[int, int, str]] = []
    v6: List[Tuple[int, int, str]] = []

    for ioc in iocs:
        if ioc.is_expired(now):
            continue
        snap.iocs[ioc.id] = ioc
        t = ioc.ioc_type
        if t in _EXACT_TYPES:
            snap.exact[ioc.value] = ioc.id
            exact_values.append(ioc.value)
        elif t == IOCType.DOMAIN:
            _trie_insert(snap.domain_root, ioc.value, ioc.id)
            exact_values.append(ioc.value)     # bloom covers domains too
        elif t == IOCType.CIDR:
            try:
                net = ipaddress.ip_network(ioc.value, strict=False)
            except ValueError:
                continue
            lo = int(net.network_address)
            hi = int(net.broadcast_address)
            (v4 if net.version == 4 else v6).append((lo, hi, ioc.id))
        # ADVISORY and any unknown type are reporting-only: indexed in iocs, not matched.

    v4.sort()
    v6.sort()
    snap.v4_ranges = v4
    snap.v4_starts = [r[0] for r in v4]
    snap.v6_ranges = v6
    snap.v6_starts = [r[0] for r in v6]

    bloom = BloomFilter(capacity=max(1, len(exact_values)), error_rate=bloom_error_rate)
    bloom.add_all(exact_values)
    snap.bloom = bloom
    return snap


def _trie_insert(root: _TrieNode, domain: str, ioc_id: str) -> None:
    node = root
    for label in reversed(domain.split(".")):
        node = node.children.setdefault(label, _TrieNode())
    node.ioc_id = ioc_id


def _trie_match(root: _TrieNode, domain: str) -> Optional[str]:
    """Return the ioc_id of the shortest registered suffix of ``domain``.

    Walk from the TLD inward; the first terminal node we cross is a flagged
    parent domain, so ``login.evil.com`` matches a stored ``evil.com``.
    """
    node = root
    for label in reversed(domain.split(".")):
        node = node.children.get(label)
        if node is None:
            return None
        if node.ioc_id is not None:
            return node.ioc_id       # shortest matching suffix wins
    return node.ioc_id if node else None


class LookupEngine:
    """Read-mostly lookup over the current :class:`Snapshot` with an LRU cache."""

    def __init__(self, snapshot: Optional[Snapshot] = None, *, lru_size: int = 4096,
                 metrics=None):
        self._snap = snapshot or Snapshot()
        self._lru: "OrderedDict[str, Optional[MatchResult]]" = OrderedDict()
        self._lru_size = max(0, lru_size)
        self._metrics = metrics

    def swap(self, snapshot: Snapshot) -> None:
        """Atomically replace the index (double-buffer) and drop the stale cache."""
        self._snap = snapshot            # single reference assignment -> atomic under GIL
        self._lru.clear()

    @property
    def snapshot(self) -> Snapshot:
        return self._snap

    @property
    def size(self) -> int:
        return self._snap.size

    def lookup(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[MatchResult]:
        snap = self._snap                # read once: lookups never see a half-built swap
        t = IOCType.coerce(ioc_type) if ioc_type is not None else detect_type(value)
        if t is None:
            return None
        try:
            canon = canonicalize(t, value)
        except Exception:
            return None

        cache_key = f"{t.value}|{canon}"
        if self._lru_size and cache_key in self._lru:
            self._lru.move_to_end(cache_key)
            if self._metrics:
                self._metrics.incr("bt_intel_lookup_cache_hit")
            return self._lru[cache_key]

        result = self._resolve(snap, t, canon)
        self._cache_put(cache_key, result)
        if self._metrics:
            self._metrics.incr("bt_intel_lookup", hit=str(result is not None))
        return result

    def _resolve(self, snap: Snapshot, t: IOCType, canon: str) -> Optional[MatchResult]:
        if t == IOCType.CIDR:
            t = IOCType.IP              # a bare address is looked up against CIDR ranges
        if t == IOCType.IP:
            return self._match_ip(snap, canon)
        if t == IOCType.DOMAIN:
            # exact host first, then suffix trie (subdomain of a flagged parent)
            hit = snap.exact.get(canon)
            if hit is not None:
                return self._result(snap, hit, canon, "exact")
            ioc_id = _trie_match(snap.domain_root, canon)
            if ioc_id is not None:
                return self._result(snap, ioc_id, canon, "domain_suffix")
            return None
        # all other types: exact only, guarded by the bloom negative fast path
        if snap.bloom is not None and not snap.bloom.maybe_contains(canon):
            return None
        hit = snap.exact.get(canon)
        return self._result(snap, hit, canon, "exact") if hit is not None else None

    def _match_ip(self, snap: Snapshot, canon: str) -> Optional[MatchResult]:
        # exact IP IOC first (bloom-guarded)
        if not (snap.bloom is not None and not snap.bloom.maybe_contains(canon)):
            hit = snap.exact.get(canon)
            if hit is not None:
                return self._result(snap, hit, canon, "exact")
        try:
            ip_int = int(ipaddress.ip_address(canon))
            ver = ipaddress.ip_address(canon).version
        except ValueError:
            return None
        starts = snap.v4_starts if ver == 4 else snap.v6_starts
        ranges = snap.v4_ranges if ver == 4 else snap.v6_ranges
        if not starts:
            return None
        # rightmost range whose start <= ip; check its end. ranges are sorted by start.
        idx = bisect.bisect_right(starts, ip_int) - 1
        if idx < 0:
            return None
        lo, hi, ioc_id = ranges[idx]
        if lo <= ip_int <= hi:
            return self._result(snap, ioc_id, canon, "cidr")
        return None

    def _result(self, snap: Snapshot, ioc_id: str, query: str, reason: str) -> Optional[MatchResult]:
        ioc = snap.iocs.get(ioc_id)
        if ioc is None:
            return None
        return MatchResult(
            ioc_id=ioc_id, ioc_type=ioc.ioc_type, matched_value=ioc.value,
            query_value=query, reason=reason, confidence=ioc.confidence,
            severity=ioc.severity, sources=tuple(ioc.sources))

    def _cache_put(self, key: str, value: Optional[MatchResult]) -> None:
        if not self._lru_size:
            return
        self._lru[key] = value
        self._lru.move_to_end(key)
        while len(self._lru) > self._lru_size:
            self._lru.popitem(last=False)


__all__ = ["LookupEngine", "Snapshot", "MatchResult", "build_snapshot"]
