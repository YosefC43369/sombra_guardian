"""
web_footprint.config — run modes and passive-pivot limits for the Web Footprint
Intelligence Engine.

Two orthogonal knobs govern a recon run:

  * ``ReconMode``  — how *deep* the pipeline goes (which collectors and analyses
    are enabled). QUICK is a fast attack-surface sketch; STANDARD adds history,
    DNS, metadata and graph construction; DEEP adds recursive passive pivots,
    cross-source correlation and change detection. All three are PASSIVE — the
    mode never unlocks an active probe, only more public-source breadth.
  * ``ReconLimits`` — the hard ceilings that keep a run bounded: max pivot depth,
    max domains / subdomains / documents / repositories / URLs, a total request
    budget and a wall-clock runtime cap. These exist so recursive pivoting can
    never fan out without bound (spec §59). Every collector and the pipeline
    read these; nothing in the engine loops without a ceiling from here.

The presets are plain constants so a run is reproducible and a reviewer can see
exactly what each mode does. Nothing here talks to the network or reads I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class ReconMode(str, Enum):
    """Breadth/depth of a passive recon run (spec §56–58)."""

    QUICK = "quick"        # domain/subdomain/website/tech/cert/doc/repo sketch
    STANDARD = "standard"  # + archives, DNS, metadata, timelines, graph
    DEEP = "deep"          # + recursive passive pivots, correlation, change-detect

    @classmethod
    def coerce(cls, raw: Any) -> "ReconMode":
        if isinstance(raw, cls):
            return raw
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.STANDARD


@dataclass(frozen=True)
class ReconLimits:
    """Hard ceilings for a run. Defaults are conservative; DEEP mode raises a
    few of them via :meth:`for_mode`. A value of 0 is never treated as
    "unlimited" — callers clamp to at least 1 where a positive bound is needed."""

    max_pivot_depth: int = 1
    max_domains: int = 50
    max_subdomains: int = 500
    max_documents: int = 200
    max_repositories: int = 100
    max_urls: int = 1000
    max_requests: int = 400
    max_runtime_s: float = 120.0
    # Per-collector concurrency and politeness (passed to the shared HTTP client).
    concurrency: int = 6
    rate_per_host: float = 4.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_pivot_depth": self.max_pivot_depth,
            "max_domains": self.max_domains,
            "max_subdomains": self.max_subdomains,
            "max_documents": self.max_documents,
            "max_repositories": self.max_repositories,
            "max_urls": self.max_urls,
            "max_requests": self.max_requests,
            "max_runtime_s": self.max_runtime_s,
            "concurrency": self.concurrency,
            "rate_per_host": self.rate_per_host,
        }

    @classmethod
    def for_mode(cls, mode: ReconMode) -> "ReconLimits":
        if mode is ReconMode.QUICK:
            return cls(
                max_pivot_depth=0, max_domains=10, max_subdomains=150,
                max_documents=40, max_repositories=25, max_urls=300,
                max_requests=120, max_runtime_s=45.0, concurrency=6,
                rate_per_host=4.0,
            )
        if mode is ReconMode.DEEP:
            return cls(
                max_pivot_depth=2, max_domains=150, max_subdomains=2000,
                max_documents=600, max_repositories=300, max_urls=5000,
                max_requests=1500, max_runtime_s=600.0, concurrency=8,
                rate_per_host=4.0,
            )
        return cls()  # STANDARD defaults


# Which pipeline stages each mode turns on. The pipeline reads these flags; a
# collector that is off simply does not run (no network calls made).
_STAGE_MATRIX: Dict[ReconMode, Dict[str, bool]] = {
    ReconMode.QUICK: {
        "certificates": True, "subdomains": True, "wellknown": True,
        "technology": True, "documents": True, "repositories": True,
        "passive_dns": False, "archive": False, "history": False,
        "metadata": False, "graph": False, "pivots": False, "exposure": True,
    },
    ReconMode.STANDARD: {
        "certificates": True, "subdomains": True, "wellknown": True,
        "technology": True, "documents": True, "repositories": True,
        "passive_dns": True, "archive": True, "history": True,
        "metadata": True, "graph": True, "pivots": False, "exposure": True,
    },
    ReconMode.DEEP: {
        "certificates": True, "subdomains": True, "wellknown": True,
        "technology": True, "documents": True, "repositories": True,
        "passive_dns": True, "archive": True, "history": True,
        "metadata": True, "graph": True, "pivots": True, "exposure": True,
    },
}


def stages_for(mode: ReconMode) -> Dict[str, bool]:
    """The stage-enable map for a mode (a copy, so callers can override)."""
    return dict(_STAGE_MATRIX[ReconMode.coerce(mode)])


@dataclass
class ReconConfig:
    """The full, resolved configuration for one recon run."""

    mode: ReconMode = ReconMode.STANDARD
    limits: ReconLimits = None  # type: ignore[assignment]
    stages: Dict[str, bool] = field(default_factory=dict)
    # RED_TEAM_WEIGHT / BLUE_TEAM_WEIGHT document the engine's 80/20 posture
    # (spec: red-team passive recon is primary; blue-team monitoring secondary).
    red_team_weight: float = 0.8
    blue_team_weight: float = 0.2

    def __post_init__(self) -> None:
        self.mode = ReconMode.coerce(self.mode)
        if self.limits is None:
            self.limits = ReconLimits.for_mode(self.mode)
        if not self.stages:
            self.stages = stages_for(self.mode)

    def enabled(self, stage: str) -> bool:
        return bool(self.stages.get(stage, False))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "limits": self.limits.to_dict(),
            "stages": dict(self.stages),
            "red_team_weight": self.red_team_weight,
            "blue_team_weight": self.blue_team_weight,
        }
