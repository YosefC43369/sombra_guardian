"""
blueteam/config.py — feature flags, tier kill-switches and tunables, read through
``envutil`` with safe defaults (กติกา: config ผ่าน envutil พร้อม validation).

Two layers of control:

  * **Global flags** (env) — a master kill switch plus one flag per module so the
    suite can be sold/enabled in tiers, and global allow-gates for the *opt-in*
    external services (VirusTotal/Safe Browsing/urlscan) and the active probe,
    both OFF by default (privacy/safety).
  * **Per-group policy** (DB, ``bt_group_policy``) — even when a module's global
    flag is on, it does nothing in a group until an admin turns it on and picks a
    mode/threshold. So the safe default everywhere is "inactive".

Nothing here talks to the network or Telegram; values are read at call time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import envutil


@dataclass(frozen=True)
class BlueTeamConfig:
    # master + per-module (tiering)
    enabled: bool
    linkguard_enabled: bool
    scamguard_enabled: bool
    joinguard_enabled: bool
    # external / active capabilities (default OFF — opt-in per group too)
    external_enabled: bool          # global allow for VT/GSB/urlscan
    active_probe_enabled: bool      # global allow for tier-3 redirect/TLS probe
    # secrets / keys (names only read here; values used by callers)
    hmac_secret_env: str
    # limits / tunables
    retention_days: int
    campaign_buffer: int            # SimHash ring-buffer size per chat
    join_buffer: int                # join-event ring-buffer size per chat
    probe_concurrency: int
    probe_per_host_rate: float
    probe_timeout_s: float
    probe_max_hops: int
    probe_max_bytes: int
    linkcheck_cooldown_s: int       # per-user /linkcheck rate limit

    @classmethod
    def load(cls) -> "BlueTeamConfig":
        return cls(
            enabled=envutil.env_bool("BLUETEAM_ENABLED", "true"),
            linkguard_enabled=envutil.env_bool("BLUETEAM_LINKGUARD_ENABLED", "true"),
            scamguard_enabled=envutil.env_bool("BLUETEAM_SCAMGUARD_ENABLED", "true"),
            joinguard_enabled=envutil.env_bool("BLUETEAM_JOINGUARD_ENABLED", "true"),
            external_enabled=envutil.env_bool("BLUETEAM_EXTERNAL_ENABLED", "false"),
            active_probe_enabled=envutil.env_bool("BLUETEAM_ACTIVE_PROBE_ENABLED", "false"),
            hmac_secret_env=envutil.raw("BLUETEAM_HMAC_SECRET", ""),
            retention_days=max(1, envutil.env_int("BLUETEAM_RETENTION_DAYS", 90)),
            campaign_buffer=max(64, envutil.env_int("BLUETEAM_CAMPAIGN_BUFFER", 512)),
            join_buffer=max(64, envutil.env_int("BLUETEAM_JOIN_BUFFER", 512)),
            probe_concurrency=max(1, envutil.env_int("BLUETEAM_PROBE_CONCURRENCY", 4)),
            probe_per_host_rate=max(0.1, envutil.env_float("BLUETEAM_PROBE_PER_HOST_RATE", 1.0)),
            probe_timeout_s=max(1.0, envutil.env_float("BLUETEAM_PROBE_TIMEOUT_S", 8.0)),
            probe_max_hops=max(1, envutil.env_int("BLUETEAM_PROBE_MAX_HOPS", 5)),
            probe_max_bytes=max(4096, envutil.env_int("BLUETEAM_PROBE_MAX_BYTES", 65536)),
            linkcheck_cooldown_s=max(0, envutil.env_int("BLUETEAM_LINKCHECK_COOLDOWN_S", 15)),
        )

    def module_enabled(self, module: str) -> bool:
        if not self.enabled:
            return False
        return {
            "linkguard": self.linkguard_enabled,
            "scamguard": self.scamguard_enabled,
            "impersonation": self.scamguard_enabled,
            "joinguard": self.joinguard_enabled,
        }.get(module, True)


_config: Optional[BlueTeamConfig] = None


def get_config(refresh: bool = False) -> BlueTeamConfig:
    global _config
    if _config is None or refresh:
        _config = BlueTeamConfig.load()
    return _config
