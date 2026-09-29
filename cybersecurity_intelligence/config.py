"""
cybersecurity_intelligence.config — resolved, typed CTI-analysis settings.

Follows the exact repo config discipline (see ``config.py``,
``threat_actor_intelligence.configuration``, ``blueteam.config``): standard
library only, every value read from the environment *at call time* (never at
import, because ``app.py`` loads the .env after its import block), no secret is
ever logged, and every setting has a safe default so the analytic core runs with
zero configuration.

All ``CTI_*`` knobs from the master spec (§110) live here. Provider API keys are
never stored on the object — the ingestion those feed lives in
``threat_actor_intelligence`` and resolves its own keys; this layer only holds
the analysis/limits/retention knobs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


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


@dataclass
class CTIConfig:
    """Runtime configuration for the CTI Analysis Engine.

    The defaults are deliberately conservative and offline-safe: alerts off,
    graph on, trend analysis on, a shared DB path with the actor-intel engine so
    the analytic layer reads the same evidence it grades.
    """

    # -- master switch + storage --------------------------------------------- #
    enabled: bool = True
    db_path: str = "cybersecurity_intelligence.db"
    cache_ttl_seconds: int = 21600            # 6h analysis cache TTL

    # -- ingestion / performance limits (§101, §102, §110) ------------------- #
    refresh_interval_seconds: int = 3600
    max_concurrency: int = 8
    request_timeout_seconds: float = 20.0
    max_article_size_bytes: int = 2_000_000   # 2 MB hard cap per article
    max_document_size_bytes: int = 10_000_000  # 10 MB hard cap per document
    max_results: int = 500                     # default paging cap
    rate_limit_per_min: float = 60.0

    # -- retention (§105) ---------------------------------------------------- #
    retention_days: int = 365

    # -- analytic feature toggles (§110) ------------------------------------- #
    enable_alerts: bool = False
    enable_graph: bool = True
    enable_trend_analysis: bool = True

    # -- corroboration / confidence knobs ------------------------------------ #
    corroboration_min_independent_sources: int = 2

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_config() -> CTIConfig:
    """Resolve CTI configuration from the environment. Call at runtime."""
    return CTIConfig(
        enabled=_env_bool("CTI_ENABLED", True),
        db_path=_env("CTI_DB_PATH", "cybersecurity_intelligence.db"),
        cache_ttl_seconds=_env_int("CTI_CACHE_TTL", 21600),
        refresh_interval_seconds=_env_int("CTI_REFRESH_INTERVAL", 3600),
        max_concurrency=_env_int("CTI_MAX_CONCURRENCY", 8),
        request_timeout_seconds=_env_float("CTI_REQUEST_TIMEOUT", 20.0),
        max_article_size_bytes=_env_int("CTI_MAX_ARTICLE_SIZE", 2_000_000),
        max_document_size_bytes=_env_int("CTI_MAX_DOCUMENT_SIZE", 10_000_000),
        max_results=_env_int("CTI_MAX_RESULTS", 500),
        rate_limit_per_min=_env_float("CTI_RATE_LIMIT", 60.0),
        retention_days=_env_int("CTI_RETENTION_DAYS", 365),
        enable_alerts=_env_bool("CTI_ENABLE_ALERTS", False),
        enable_graph=_env_bool("CTI_ENABLE_GRAPH", True),
        enable_trend_analysis=_env_bool("CTI_ENABLE_TREND_ANALYSIS", True),
        corroboration_min_independent_sources=_env_int(
            "CTI_CORROBORATION_MIN_SOURCES", 2),
    )


__all__ = ["CTIConfig", "get_config"]
