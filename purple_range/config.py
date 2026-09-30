"""
purple_range/config.py — feature flags / tunables via envutil (repo idiom).

Master switch is OFF by default: shipping the code changes nothing until an admin turns
it on. The SOC-replay bridge is separately gated and also OFF by default.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional

import envutil


@dataclass(frozen=True)
class PurpleRangeConfig:
    enabled: bool                 # master switch (OFF by default)
    soc_bridge_enabled: bool      # allow replaying synthetic telemetry into group_soc
    telemetry_max_events: int     # cap on events a single generation may return
    default_seed: int             # deterministic-generation seed base

    @classmethod
    def load(cls) -> "PurpleRangeConfig":
        return cls(
            enabled=envutil.env_bool("PURPLE_RANGE_ENABLED", "false"),
            soc_bridge_enabled=envutil.env_bool("PURPLE_RANGE_SOC_BRIDGE_ENABLED", "false"),
            telemetry_max_events=max(1, envutil.env_int("PURPLE_RANGE_TELEMETRY_MAX_EVENTS", 200)),
            default_seed=envutil.env_int("PURPLE_RANGE_SEED", 1337),
        )

    def as_dict(self) -> dict:
        return asdict(self)


_config: Optional[PurpleRangeConfig] = None


def get_config(refresh: bool = False) -> PurpleRangeConfig:
    global _config
    if _config is None or refresh:
        _config = PurpleRangeConfig.load()
    return _config
