"""
behavioral_intelligence.configuration — resolved, typed settings for the engine.

Follows the repo's config discipline (see ``config.py``): stdlib only, values
read from the environment at call time (never at import — ``app.py`` loads the
.env after its import block), never logs a secret value. Everything has a safe
default so the analytical core runs with zero configuration; environment
variables tune storage location, baseline windows, privacy posture and provider
rate limits.

All credentials (provider API keys) come from the environment — none are ever
hardcoded here (spec §53).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, overload


@overload
def _env(name: str, default: str) -> str: ...
@overload
def _env(name: str, default: None = None) -> Optional[str]: ...


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v.strip() if v and v.strip() else default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = _env(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")


def _env_list(name: str, default: List[int]) -> List[int]:
    v = _env(name)
    if not v:
        return list(default)
    out: List[int] = []
    for part in v.split(","):
        part = part.strip()
        if part:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return out or list(default)


@dataclass
class PrivacyConfig:
    """Data-minimisation posture (spec §34). Redaction is ON by default: the
    engine keeps hashes and derived statistics, and drops raw text unless
    explicitly told to retain it."""
    retain_raw_text: bool = False
    redact_pii_in_reports: bool = True
    evidence_ttl_days: int = 180
    observation_ttl_days: int = 365
    mask_account_ids: bool = False       # hash account ids in rendered reports
    max_sample_text_chars: int = 240     # truncate any text shown in a report

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderConfig:
    """Passive-collection safety knobs (spec §52, §54). The engine is a polite,
    read-only client: it honours robots.txt, per-host rate limits and timeouts,
    and never authenticates against, bypasses or brute-forces anything."""
    user_agent: str = "SombraGuardian-Behavioral/1.0 (+authorized-assessment)"
    per_host_rate: float = 1.0           # requests/second/host
    per_host_burst: int = 3
    timeout_seconds: float = 20.0
    max_retries: int = 3
    respect_robots_txt: bool = True
    max_concurrency: int = 8

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BehavioralConfig:
    """Top-level engine configuration."""
    db_path: str = "behavioral_intelligence.db"
    cache_dir: str = ".behavioral_cache"
    default_timezone_offset_hours: float = 0.0
    baseline_windows_days: List[int] = field(default_factory=lambda: [7, 30, 90])
    burst_window_minutes: int = 15
    inactivity_min_days: int = 7
    changepoint_zscore_threshold: float = 3.0
    min_sample_for_pattern: int = 5
    max_observations_in_memory: int = 250_000    # large-dataset streaming trigger
    top_keywords: int = 25
    top_hashtags: int = 25
    top_domains: int = 25
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    provider: ProviderConfig = field(default_factory=ProviderConfig)

    @classmethod
    def from_env(cls) -> "BehavioralConfig":
        return cls(
            db_path=_env("BEHAVIORAL_DB_PATH", "behavioral_intelligence.db"),
            cache_dir=_env("BEHAVIORAL_CACHE_DIR", ".behavioral_cache"),
            default_timezone_offset_hours=_env_float(
                "BEHAVIORAL_TZ_OFFSET_HOURS", 0.0),
            baseline_windows_days=_env_list(
                "BEHAVIORAL_BASELINE_WINDOWS", [7, 30, 90]),
            burst_window_minutes=_env_int("BEHAVIORAL_BURST_WINDOW_MIN", 15),
            inactivity_min_days=_env_int("BEHAVIORAL_INACTIVITY_MIN_DAYS", 7),
            changepoint_zscore_threshold=_env_float(
                "BEHAVIORAL_CHANGEPOINT_Z", 3.0),
            min_sample_for_pattern=_env_int("BEHAVIORAL_MIN_SAMPLE", 5),
            max_observations_in_memory=_env_int(
                "BEHAVIORAL_MAX_IN_MEMORY", 250_000),
            top_keywords=_env_int("BEHAVIORAL_TOP_KEYWORDS", 25),
            top_hashtags=_env_int("BEHAVIORAL_TOP_HASHTAGS", 25),
            top_domains=_env_int("BEHAVIORAL_TOP_DOMAINS", 25),
            privacy=PrivacyConfig(
                retain_raw_text=_env_bool("BEHAVIORAL_RETAIN_TEXT", False),
                redact_pii_in_reports=_env_bool("BEHAVIORAL_REDACT_PII", True),
                evidence_ttl_days=_env_int("BEHAVIORAL_EVIDENCE_TTL_DAYS", 180),
                observation_ttl_days=_env_int("BEHAVIORAL_OBS_TTL_DAYS", 365),
                mask_account_ids=_env_bool("BEHAVIORAL_MASK_ACCOUNTS", False),
                max_sample_text_chars=_env_int("BEHAVIORAL_MAX_SAMPLE_CHARS", 240),
            ),
            provider=ProviderConfig(
                user_agent=_env("BEHAVIORAL_USER_AGENT",
                                ProviderConfig.user_agent),
                per_host_rate=_env_float("BEHAVIORAL_RATE", 1.0),
                per_host_burst=_env_int("BEHAVIORAL_BURST", 3),
                timeout_seconds=_env_float("BEHAVIORAL_TIMEOUT", 20.0),
                max_retries=_env_int("BEHAVIORAL_MAX_RETRIES", 3),
                respect_robots_txt=_env_bool("BEHAVIORAL_RESPECT_ROBOTS", True),
                max_concurrency=_env_int("BEHAVIORAL_MAX_CONCURRENCY", 8),
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# A module-level default so callers that don't thread config through can still
# read sensible values. Constructed lazily via get_config().
_CONFIG: Optional[BehavioralConfig] = None


def get_config(refresh: bool = False) -> BehavioralConfig:
    global _CONFIG
    if _CONFIG is None or refresh:
        _CONFIG = BehavioralConfig.from_env()
    return _CONFIG
