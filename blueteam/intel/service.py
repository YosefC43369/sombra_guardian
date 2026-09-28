"""
blueteam/intel/service.py — Intel orchestration (feed sync, ingest, lookup,
local IOCs, export). Depends only on ports (Protocols) + the pure core, never on
sqlite/telegram directly, so it is unit-tested with in-memory fakes.

Ingest is **staged and atomic**: parse -> screen (poisoning guard) -> confidence
-> repository upsert -> rebuild lookup snapshot and swap. A feed that fails at any
stage leaves the live snapshot untouched (fail-open for detection: we keep serving
the last good index).

Feed-poisoning guard (spec D3):
  * a small built-in allowlist of high-reputation registrable domains plus the
    operator whitelist table are **never ingested as malicious**;
  * **growth quarantine**: if a feed suddenly returns far more items than its last
    good sync (ratio over a threshold), the sync is quarantined, not ingested.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from .. import urlkit
from .domain import (IOC, IOCType, TLP, canonicalize, compute_confidence,
                     detect_type, ioc_id, to_stix_bundle, CanonicalizeError,
                     DEFAULT_SOURCE_WEIGHTS)
from .feeds import FeedDef, FeedFetcher, ParsedIOC, parse_feed
from .lookup import LookupEngine, MatchResult, build_snapshot

# Never treat these registrable domains as malicious even if a feed lists them.
_BUILTIN_ALLOWLIST = frozenset({
    "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com",
    "x.com", "apple.com", "microsoft.com", "amazon.com", "cloudflare.com",
    "wikipedia.org", "github.com", "telegram.org", "t.me", "line.me",
    "whatsapp.com", "gov.uk", "who.int",
})


class IocRepository(Protocol):
    def upsert_iocs(self, iocs: List[IOC], now: float) -> int: ...
    def all_active_iocs(self, now: float) -> List[IOC]: ...
    def get_ioc(self, the_id: str) -> Optional[IOC]: ...
    def delete_ioc(self, the_id: str) -> bool: ...
    def record_sighting(self, the_id: str, chat_id: Optional[int],
                        user_id: Optional[int], context: str, now: float) -> None: ...
    def sightings_for(self, the_id: str, limit: int) -> List[Dict[str, Any]]: ...
    def add_whitelist(self, value: str, added_by: Optional[int], now: float) -> None: ...
    def remove_whitelist(self, value: str) -> bool: ...
    def list_whitelist(self) -> List[str]: ...
    def get_feed_state(self, feed: str) -> Dict[str, Any]: ...
    def save_feed_state(self, feed: str, state: Dict[str, Any]) -> None: ...
    def list_feed_states(self) -> List[Dict[str, Any]]: ...
    def stats(self) -> Dict[str, Any]: ...


class IntelService:
    def __init__(self, repo: IocRepository, *, feeds: Dict[str, FeedDef],
                 fetcher: Optional[FeedFetcher] = None, clock: Callable[[], float] = time.time,
                 metrics=None, emit: Optional[Callable[[Any], None]] = None,
                 growth_quarantine_ratio: float = 10.0,
                 growth_quarantine_floor: int = 500,
                 auto_action_min_confidence: int = 75,
                 source_weights: Optional[Dict[str, float]] = None):
        self._repo = repo
        self._feeds = feeds
        self._fetcher = fetcher
        self._clock = clock
        self._metrics = metrics
        self._emit = emit or (lambda e: None)
        self._growth_ratio = growth_quarantine_ratio
        self._growth_floor = growth_quarantine_floor
        self._min_conf = auto_action_min_confidence
        self._weights = source_weights or dict(DEFAULT_SOURCE_WEIGHTS)
        self._engine = LookupEngine(build_snapshot(repo.all_active_iocs(self._clock()),
                                                   now=self._clock()), metrics=metrics)

    # ---------------- lookup ----------------
    @property
    def engine(self) -> LookupEngine:
        return self._engine

    def lookup(self, value: str, ioc_type: Optional[IOCType] = None,
               *, chat_id: Optional[int] = None, user_id: Optional[int] = None,
               record: bool = False) -> Optional[MatchResult]:
        mr = self._engine.lookup(value, ioc_type)
        if mr and record:
            try:
                self._repo.record_sighting(mr.ioc_id, chat_id, user_id,
                                           mr.reason, self._clock())
            except Exception:
                pass
        if mr and self._metrics:
            self._metrics.incr("bt_intel_match", severity=mr.severity)
        return mr

    def refresh_engine(self) -> int:
        now = self._clock()
        snap = build_snapshot(self._repo.all_active_iocs(now), now=now)
        self._engine.swap(snap)
        return snap.size

    # ---------------- ingest / feed sync ----------------
    def _is_allowlisted(self, p: ParsedIOC, operator_wl: frozenset) -> bool:
        if p.ioc_type in (IOCType.DOMAIN, IOCType.URL):
            host = p.value if p.ioc_type == IOCType.DOMAIN else urlkit.canonicalize(p.value)
            try:
                reg = urlkit.registrable_domain(host.split("/")[0])
            except Exception:
                reg = host
            if reg in _BUILTIN_ALLOWLIST or reg in operator_wl or p.value in operator_wl:
                return True
        return p.value in operator_wl

    def sync_feed(self, name: str) -> Dict[str, Any]:
        feed = self._feeds.get(name)
        now = self._clock()
        if feed is None:
            return {"feed": name, "status": "unknown", "ingested": 0}
        if not feed.license_ok:
            return {"feed": name, "status": "license_blocked", "ingested": 0}
        if self._fetcher is None:
            return {"feed": name, "status": "no_fetcher", "ingested": 0}

        st = self._repo.get_feed_state(name) or {}
        res = self._fetcher.fetch(feed, etag=st.get("etag", ""),
                                  last_modified=st.get("last_modified", ""))
        if res.status == 304:
            self._save_state(name, feed, st, status="not_modified", now=now)
            return {"feed": name, "status": "not_modified", "ingested": 0}
        if res.status != 200:
            self._save_state(name, feed, st, status=f"error:{res.error or res.status}",
                             now=now, bump_fail=True)
            self._emit(_feed_failed(name, res.error or f"http {res.status}", now))
            return {"feed": name, "status": "error", "error": res.error, "ingested": 0}

        parsed = parse_feed(feed, res.body)
        # growth quarantine
        last_count = int(st.get("item_count", 0) or 0)
        if (last_count >= self._growth_floor and parsed
                and len(parsed) > last_count * self._growth_ratio):
            self._save_state(name, feed, st, status="quarantined_growth", now=now,
                             bump_fail=True, etag=res.etag, last_modified=res.last_modified)
            self._emit(_feed_failed(name, f"growth quarantine {last_count}->{len(parsed)}", now))
            return {"feed": name, "status": "quarantined", "seen": len(parsed), "ingested": 0}

        operator_wl = frozenset(self._repo.list_whitelist())
        iocs: List[IOC] = []
        for p in parsed:
            if self._is_allowlisted(p, operator_wl):
                continue
            conf, breakdown = compute_confidence(sources=[name], age_days=0.0,
                                                  source_weights=self._weights)
            expires = now + feed.default_ttl_days * 86400
            iocs.append(IOC(ioc_type=p.ioc_type, value=p.value, sources=[name],
                            first_seen=now, last_seen=now, expires_at=expires,
                            confidence=conf, severity=p.severity or feed.severity,
                            tlp=TLP.AMBER, tags=list(p.tags), family=p.family,
                            provenance={"feed": name, "confidence": breakdown}))
        ingested = self._repo.upsert_iocs(iocs, now)
        self._save_state(name, feed, st, status="ok", now=now, item_count=len(parsed),
                         etag=res.etag, last_modified=res.last_modified, reset_fail=True)
        self.refresh_engine()
        if self._metrics:
            self._metrics.incr("bt_intel_feed_sync", feed=name)
            self._metrics.gauge("bt_intel_ioc_count", self._engine.size)
        self._emit(_feed_synced(name, ingested, len(parsed), now))
        return {"feed": name, "status": "ok", "seen": len(parsed), "ingested": ingested}

    def sync_all(self, *, only_enabled: bool = True) -> List[Dict[str, Any]]:
        out = []
        for name, feed in self._feeds.items():
            st = self._repo.get_feed_state(name) or {}
            enabled = st.get("enabled")
            if enabled is None:
                enabled = feed.enabled_default
            if only_enabled and not enabled:
                out.append({"feed": name, "status": "disabled", "ingested": 0})
                continue
            out.append(self.sync_feed(name))
        return out

    def _save_state(self, name: str, feed: FeedDef, prev: Dict[str, Any], *, status: str,
                    now: float, item_count: Optional[int] = None, etag: str = "",
                    last_modified: str = "", bump_fail: bool = False,
                    reset_fail: bool = False) -> None:
        state = dict(prev)
        state.update({"feed": name, "url": feed.url, "last_sync": now, "last_status": status})
        if item_count is not None:
            state["item_count"] = item_count
        if etag:
            state["etag"] = etag
        if last_modified:
            state["last_modified"] = last_modified
        fails = int(prev.get("failures", 0) or 0)
        state["failures"] = 0 if reset_fail else (fails + 1 if bump_fail else fails)
        self._repo.save_feed_state(name, state)

    # ---------------- local IOCs (admin) ----------------
    def add_local(self, raw_value: str, *, ioc_type: Optional[IOCType] = None,
                  severity: str = "high", ttl_days: int = 0, tags: Optional[List[str]] = None,
                  added_by: Optional[int] = None) -> Optional[IOC]:
        t = ioc_type or detect_type(raw_value)
        if t is None:
            return None
        try:
            canon = canonicalize(t, raw_value)
        except CanonicalizeError:
            return None
        now = self._clock()
        conf, breakdown = compute_confidence(sources=["local"], age_days=0.0,
                                             local_verdict=True, source_weights=self._weights)
        ioc = IOC(ioc_type=t, value=canon, sources=["local"], first_seen=now, last_seen=now,
                  expires_at=(now + ttl_days * 86400) if ttl_days else None,
                  confidence=conf, severity=severity, tlp=TLP.AMBER,
                  tags=list(tags or []), is_local=True,
                  provenance={"added_by": added_by, "confidence": breakdown})
        self._repo.upsert_iocs([ioc], now)
        self.refresh_engine()
        return ioc

    def delete_local(self, raw_value: str, ioc_type: Optional[IOCType] = None) -> bool:
        t = ioc_type or detect_type(raw_value)
        if t is None:
            return False
        try:
            canon = canonicalize(t, raw_value)
        except CanonicalizeError:
            return False
        ok = self._repo.delete_ioc(ioc_id(t, canon))
        if ok:
            self.refresh_engine()
        return ok

    def add_whitelist(self, value: str, added_by: Optional[int] = None) -> None:
        self._repo.add_whitelist(value.strip().lower(), added_by, self._clock())

    def remove_whitelist(self, value: str) -> bool:
        return self._repo.remove_whitelist(value.strip().lower())

    def list_whitelist(self) -> List[str]:
        return self._repo.list_whitelist()

    # ---------------- export / status ----------------
    def export_stix(self, *, ioc_type: Optional[IOCType] = None,
                    min_confidence: int = 0, limit: int = 5000) -> Dict[str, Any]:
        now = self._clock()
        iocs = [i for i in self._repo.all_active_iocs(now)
                if (ioc_type is None or i.ioc_type == ioc_type)
                and i.confidence >= min_confidence][:limit]
        return to_stix_bundle(iocs)

    def sightings(self, raw_value: str, ioc_type: Optional[IOCType] = None,
                  limit: int = 20) -> List[Dict[str, Any]]:
        t = ioc_type or detect_type(raw_value)
        if t is None:
            return []
        try:
            canon = canonicalize(t, raw_value)
        except CanonicalizeError:
            return []
        return self._repo.sightings_for(ioc_id(t, canon), limit)

    def feed_status(self) -> List[Dict[str, Any]]:
        states = {s["feed"]: s for s in self._repo.list_feed_states()}
        out = []
        for name, feed in self._feeds.items():
            st = states.get(name, {})
            enabled = st.get("enabled")
            out.append({
                "feed": name, "license": feed.license, "license_ok": feed.license_ok,
                "enabled": feed.enabled_default if enabled is None else bool(enabled),
                "last_sync": st.get("last_sync"), "last_status": st.get("last_status", "never"),
                "item_count": st.get("item_count", 0), "failures": st.get("failures", 0),
            })
        return out

    def stats(self) -> Dict[str, Any]:
        s = dict(self._repo.stats())
        s["engine_size"] = self._engine.size
        return s

    def health(self) -> Dict[str, Any]:
        states = self._repo.list_feed_states()
        failing = [s["feed"] for s in states if int(s.get("failures", 0) or 0) >= 3]
        return {"ok": not failing, "engine_size": self._engine.size,
                "feeds": len(self._feeds), "failing_feeds": failing}


# ---------------- event helpers (import events lazily to keep layering clean) ----------------

def _feed_synced(feed: str, ingested: int, seen: int, ts: float):
    from ..platform.events import FeedSynced
    return FeedSynced(feed=feed, added=ingested, total=seen, ts=ts)


def _feed_failed(feed: str, error: str, ts: float):
    from ..platform.events import FeedFailed
    return FeedFailed(feed=feed, reason=error, ts=ts)


__all__ = ["IntelService", "IocRepository"]
