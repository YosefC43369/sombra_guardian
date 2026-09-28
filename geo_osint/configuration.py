"""
geo_osint.configuration — run modes and hard limits for a Geo-OSINT run.

Two orthogonal knobs govern a run, mirroring the pattern the ``web_footprint``
engine already establishes:

  * :class:`GeoMode` — how *deep* the pipeline goes (which engines/collectors run).
    LOCAL never touches the network (offline gazetteer, coordinate math, airports
    DB only); PASSIVE adds public network sources (Nominatim, Wikidata, GeoNames,
    RDAP, IP/ASN providers); DEEP adds recursive geographic pivoting and
    cross-source correlation. No mode ever unlocks a private or active capability
    — only more *public* breadth.
  * :class:`GeoLimits` — the ceilings that keep a run bounded: request budget,
    wall-clock cap, per-source concurrency/rate, max entities/observations/pivots,
    and the proximity radius cap.

All presets are plain, reviewable constants. Nothing here performs I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class GeoMode(str, Enum):
    LOCAL = "local"        # offline only: gazetteer, coord math, airports DB
    PASSIVE = "passive"    # + public network sources (OSM/Wikidata/GeoNames/RDAP)
    DEEP = "deep"          # + recursive public pivots + cross-source correlation

    @classmethod
    def coerce(cls, raw: Any) -> "GeoMode":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.PASSIVE

    @property
    def uses_network(self) -> bool:
        return self is not GeoMode.LOCAL


@dataclass(frozen=True)
class GeoLimits:
    """Hard ceilings for a run. Defaults are conservative and polite."""

    max_requests: int = 300
    max_runtime_s: float = 120.0
    max_entities: int = 200
    max_observations: int = 5000
    max_pivot_depth: int = 1
    max_neighbors: int = 25
    max_proximity_radius_km: float = 500.0
    default_proximity_radius_km: float = 50.0
    http_rate: float = 3.0            # requests/sec per host (politeness)
    http_burst: int = 3
    http_timeout_s: float = 20.0
    http_max_retries: int = 2
    # Nominatim's usage policy is <=1 req/s; the OSM client clamps to this.
    nominatim_rate: float = 1.0

    def for_mode(self, mode: GeoMode) -> "GeoLimits":
        if mode is GeoMode.LOCAL:
            return GeoLimits(max_requests=0, max_runtime_s=self.max_runtime_s,
                             max_entities=self.max_entities,
                             max_observations=self.max_observations,
                             max_pivot_depth=0, max_neighbors=self.max_neighbors,
                             max_proximity_radius_km=self.max_proximity_radius_km,
                             default_proximity_radius_km=self.default_proximity_radius_km)
        if mode is GeoMode.DEEP:
            return GeoLimits(max_requests=800, max_runtime_s=300.0,
                             max_entities=500, max_observations=20000,
                             max_pivot_depth=2, max_neighbors=self.max_neighbors,
                             max_proximity_radius_km=self.max_proximity_radius_km,
                             default_proximity_radius_km=self.default_proximity_radius_km,
                             http_rate=self.http_rate, http_burst=self.http_burst)
        return self


@dataclass
class GeoConfig:
    """The resolved configuration for one run."""

    mode: GeoMode = GeoMode.PASSIVE
    limits: GeoLimits = field(default_factory=GeoLimits)
    user_agent: str = "SombraGuardian-GeoOSINT/1.0 (+public-osint; contact via operator)"
    contact_email: str = ""
    cache_dir: str = ""
    enable_cache: bool = True
    # Per-source opt-outs (a source disabled here never runs, even in DEEP).
    disabled_sources: tuple = ()

    @classmethod
    def build(cls, mode: Any = GeoMode.PASSIVE, **kw: Any) -> "GeoConfig":
        m = GeoMode.coerce(mode)
        base = kw.pop("limits", None) or GeoLimits()
        return cls(mode=m, limits=base.for_mode(m), **kw)

    def source_enabled(self, name: str) -> bool:
        return name not in self.disabled_sources

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "user_agent": self.user_agent,
            "enable_cache": self.enable_cache,
            "disabled_sources": list(self.disabled_sources),
            "limits": {
                "max_requests": self.limits.max_requests,
                "max_runtime_s": self.limits.max_runtime_s,
                "max_entities": self.limits.max_entities,
                "max_observations": self.limits.max_observations,
                "max_pivot_depth": self.limits.max_pivot_depth,
                "max_proximity_radius_km": self.limits.max_proximity_radius_km,
            },
        }
