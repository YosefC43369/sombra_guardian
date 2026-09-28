"""
blueteam/platform/config.py — typed config for v0.8 (A8), via envutil, safe defaults.

All new env vars are documented in ``.env.example`` and ``config.ENV_REGISTRY``.
Every default is safe/off where it touches the network or shares data. Validation
clamps out-of-range values rather than crashing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import envutil


@dataclass(frozen=True)
class IntelConfig:
    enabled: bool
    auto_action_min_confidence: int      # below this, IOC match only alerts
    max_iocs_per_feed: int
    max_feed_bytes: int                  # cap on downloaded (compressed) bytes
    max_decompressed_bytes: int          # cap after decompression (bomb guard)
    max_decompress_ratio: int
    growth_quarantine_ratio: float       # per-sync growth beyond this -> quarantine round
    feed_timeout_s: float
    bloom_capacity: int
    lookup_cache_size: int
    sync_interval_s: int


@dataclass(frozen=True)
class DacConfig:
    enabled: bool
    max_rules: int
    max_ast_nodes: int
    max_regex_len: int
    max_window_s: int
    per_rule_budget_us: int              # time budget per rule per message
    slow_rule_trips: int                 # trips before circuit-breaking a rule


@dataclass(frozen=True)
class PostureConfig:
    enabled: bool
    rollup_interval_s: int
    snapshot_interval_s: int
    score_drop_alert: float              # emit posture.score_dropped on drop >= this


@dataclass(frozen=True)
class V08Config:
    intel: IntelConfig
    dac: DacConfig
    posture: PostureConfig
    retention_days: int
    batch_flush_interval_s: float
    kill_switch: bool                    # master off-switch for all v0.8 modules

    @classmethod
    def load(cls) -> "V08Config":
        b = envutil.env_bool
        i = envutil.env_int
        f = envutil.env_float
        return cls(
            kill_switch=not b("BLUETEAM_V08_ENABLED", "true"),
            retention_days=max(1, i("BLUETEAM_V08_RETENTION_DAYS", 180)),
            batch_flush_interval_s=max(0.2, f("BLUETEAM_BATCH_FLUSH_S", 2.0)),
            intel=IntelConfig(
                enabled=b("BLUETEAM_INTEL_ENABLED", "true"),
                auto_action_min_confidence=min(100, max(0, i("BLUETEAM_INTEL_AUTO_MIN_CONF", 75))),
                max_iocs_per_feed=max(100, i("BLUETEAM_INTEL_MAX_IOCS", 2_000_000)),
                max_feed_bytes=max(4096, i("BLUETEAM_INTEL_MAX_FEED_BYTES", 104_857_600)),
                max_decompressed_bytes=max(4096, i("BLUETEAM_INTEL_MAX_DECOMP_BYTES", 524_288_000)),
                max_decompress_ratio=max(2, i("BLUETEAM_INTEL_MAX_DECOMP_RATIO", 200)),
                growth_quarantine_ratio=max(1.5, f("BLUETEAM_INTEL_GROWTH_RATIO", 10.0)),
                feed_timeout_s=max(1.0, f("BLUETEAM_INTEL_FEED_TIMEOUT_S", 30.0)),
                bloom_capacity=max(1000, i("BLUETEAM_INTEL_BLOOM_CAP", 5_000_000)),
                lookup_cache_size=max(128, i("BLUETEAM_INTEL_LOOKUP_CACHE", 50_000)),
                sync_interval_s=max(300, i("BLUETEAM_INTEL_SYNC_INTERVAL_S", 3600)),
            ),
            dac=DacConfig(
                enabled=b("BLUETEAM_DAC_ENABLED", "true"),
                max_rules=max(1, i("BLUETEAM_DAC_MAX_RULES", 2000)),
                max_ast_nodes=max(10, i("BLUETEAM_DAC_MAX_NODES", 500)),
                max_regex_len=max(8, i("BLUETEAM_DAC_MAX_REGEX_LEN", 500)),
                max_window_s=max(1, i("BLUETEAM_DAC_MAX_WINDOW_S", 3600)),
                per_rule_budget_us=max(50, i("BLUETEAM_DAC_RULE_BUDGET_US", 2000)),
                slow_rule_trips=max(1, i("BLUETEAM_DAC_SLOW_TRIPS", 5)),
            ),
            posture=PostureConfig(
                enabled=b("BLUETEAM_POSTURE_ENABLED", "true"),
                rollup_interval_s=max(60, i("BLUETEAM_POSTURE_ROLLUP_S", 3600)),
                snapshot_interval_s=max(3600, i("BLUETEAM_POSTURE_SNAPSHOT_S", 86400)),
                score_drop_alert=max(1.0, f("BLUETEAM_POSTURE_DROP_ALERT", 10.0)),
            ),
        )

    def module_enabled(self, module: str) -> bool:
        if self.kill_switch:
            return False
        return {"intel": self.intel.enabled, "dac": self.dac.enabled,
                "posture": self.posture.enabled}.get(module, True)


_cfg: Optional[V08Config] = None


def get_v08_config(refresh: bool = False) -> V08Config:
    global _cfg
    if _cfg is None or refresh:
        _cfg = V08Config.load()
    return _cfg


__all__ = ["V08Config", "IntelConfig", "DacConfig", "PostureConfig", "get_v08_config"]
