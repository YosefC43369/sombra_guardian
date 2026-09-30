"""
cve_tracker.config — all operator-tunable settings, read from the environment.

Convention (matches ai_router / news / group_soc): values are read from
``os.environ`` at *call time* via :func:`get_config`, never cached at import,
because app.py calls ``load_dotenv()`` after its import block. Empty env values
are treated as unset (``envutil`` semantics), so a committed ``.env`` with blank
``CVE_*`` keys never crashes import.

The whole subsystem is DORMANT unless ``CVE_TRACKER_ENABLED=true``. Even then it
publishes nothing to a chat until that chat opts in via a subscription — the
safe default is "collect, don't broadcast".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from envutil import env_bool, env_int, env_float, env_list, raw

from .constants import (
    ABSOLUTE_MAX_RESPONSE_BYTES,
    NVD_CVE_API,
    CVE_ORG_API,
    CISA_KEV_JSON,
    GITHUB_ADVISORY_API,
    MAX_AI_SUMMARY_CHARS,
)


@dataclass(frozen=True)
class SourceConfig:
    """Per-source switches and limits. One instance per registered adapter."""

    name: str
    enabled: bool
    base_url: str
    #: Requests/second budget for this source's rate limiter.
    rate_limit_per_sec: float
    #: Max in-flight requests for this source.
    max_concurrency: int
    #: Per-request timeout (seconds).
    timeout: float
    #: How far back (days) a first/backfill sync reaches.
    backfill_days: int
    #: Optional API token env var name already resolved to its value ("" if none).
    api_token: str = ""
    #: Extra opaque knobs an adapter may read (e.g. NVD resultsPerPage).
    options: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AIConfig:
    enabled: bool
    #: Prefer the multi-provider ai_router over the single gemini client.
    prefer_router: bool
    language: str
    summary_max_chars: int
    #: Cache TTL for identical CVE→summary requests (seconds).
    cache_ttl: int
    #: Max retries of an AI call that returns invalid output before fallback.
    max_repair_attempts: int
    #: Hard ceiling on characters of structured input handed to the model.
    max_input_chars: int
    temperature: Optional[float]


@dataclass(frozen=True)
class AlertConfig:
    enabled: bool
    #: CVEs below this CVSS are never alerted unless a subscription overrides.
    min_cvss: float
    #: Global minimum severity band gate.
    min_severity: str
    #: Telegram sends/second ceiling across all CVE alerts (flood safety).
    send_rate_per_sec: float
    #: Delay between consecutive sends in one burst (seconds).
    send_delay: float
    #: Max alerts drained from the queue per scheduler tick.
    max_per_cycle: int
    #: Retry attempts for a failed Telegram send.
    max_send_retries: int
    #: Default admin/security chat id (0 = unset). Subscriptions override.
    admin_chat_id: int
    admin_topic_id: Optional[int]


@dataclass(frozen=True)
class RetentionConfig:
    #: Days to keep raw source payloads (0 = keep forever).
    raw_days: int
    #: Days to keep AI summaries.
    ai_summary_days: int
    #: Days to keep change/event rows.
    event_days: int
    #: Days to keep audit rows.
    audit_days: int
    #: Days to keep notification history.
    notification_days: int
    #: CVE core records are NEVER auto-deleted; this is advisory only.
    keep_cve_core_forever: bool = True


@dataclass(frozen=True)
class CVETrackerConfig:
    """The fully-resolved configuration snapshot for one run."""

    enabled: bool
    db_path: str
    poll_interval: int
    #: Bounded global concurrency across all source fetches.
    max_concurrent_requests: int
    request_timeout: float
    max_retries: float
    retry_base_delay: float
    retry_max_delay: float
    cache_ttl: int
    #: Hard response-size ceiling (bytes) — clamped to the absolute max.
    max_response_bytes: int
    user_agent: str
    sources: Dict[str, SourceConfig]
    ai: AIConfig
    alerts: AlertConfig
    retention: RetentionConfig

    def enabled_sources(self) -> List[SourceConfig]:
        return [s for s in self.sources.values() if s.enabled]

    def source(self, name: str) -> Optional[SourceConfig]:
        return self.sources.get(name)


def _bool(name: str, default: str) -> bool:
    return env_bool(name, default)


def _source(name: str, *, default_enabled: str, base_url: str,
            rate: float, concurrency: int, timeout: float, backfill: int,
            token_env: str = "", options: Optional[Dict[str, str]] = None) -> SourceConfig:
    key = name.upper()
    return SourceConfig(
        name=name,
        enabled=env_bool(f"CVE_{key}_ENABLED", default_enabled),
        base_url=(raw(f"CVE_{key}_BASE_URL", base_url) or base_url),
        rate_limit_per_sec=env_float(f"CVE_{key}_RATE_LIMIT", rate),
        max_concurrency=env_int(f"CVE_{key}_CONCURRENCY", concurrency),
        timeout=env_float(f"CVE_{key}_TIMEOUT", timeout),
        backfill_days=env_int(f"CVE_{key}_BACKFILL_DAYS", backfill),
        api_token=raw(token_env, "") if token_env else "",
        options=options or {},
    )


def get_config() -> CVETrackerConfig:
    """Read the full configuration from the environment. Cheap enough to call
    per scheduler tick; nothing here does I/O."""

    enabled = _bool("CVE_TRACKER_ENABLED", "false")
    db_path = raw("CVE_DATABASE_PATH", "bot.db") or "bot.db"

    global_timeout = env_float("CVE_REQUEST_TIMEOUT", 20.0)
    global_concurrency = env_int("CVE_MAX_CONCURRENT_REQUESTS", 8)

    # NVD asks unauthenticated clients to stay well under its rate window; a
    # token raises the ceiling. We keep a conservative default either way.
    nvd_token = raw("CVE_NVD_API_KEY", "") or raw("NVD_API_KEY", "")
    nvd_rate = 1.2 if nvd_token else 0.4

    gh_token = raw("CVE_GITHUB_TOKEN", "") or raw("GITHUB_TOKEN", "")

    sources: Dict[str, SourceConfig] = {}
    sources["nvd"] = _source(
        "nvd", default_enabled="true", base_url=NVD_CVE_API,
        rate=nvd_rate, concurrency=2, timeout=global_timeout, backfill=2,
        token_env="CVE_NVD_API_KEY" if nvd_token else "",
        options={"results_per_page": raw("CVE_NVD_RESULTS_PER_PAGE", "200") or "200"},
    )
    sources["cve_org"] = _source(
        "cve_org", default_enabled="true", base_url=CVE_ORG_API,
        rate=1.0, concurrency=3, timeout=global_timeout, backfill=2,
    )
    sources["cisa_kev"] = _source(
        "cisa_kev", default_enabled="true", base_url=CISA_KEV_JSON,
        rate=0.2, concurrency=1, timeout=global_timeout, backfill=3650,
    )
    sources["github_advisory"] = _source(
        "github_advisory",
        default_enabled="true" if gh_token else "false",
        base_url=GITHUB_ADVISORY_API,
        rate=1.0, concurrency=2, timeout=global_timeout, backfill=2,
        token_env="CVE_GITHUB_TOKEN" if gh_token else "",
        options={"per_page": raw("CVE_GITHUB_PER_PAGE", "100") or "100"},
    )
    sources["vendor_advisory"] = _source(
        "vendor_advisory", default_enabled="false", base_url="",
        rate=0.5, concurrency=2, timeout=global_timeout, backfill=7,
    )
    # EPSS: an enrichment feed (FIRST.org), not a discovery source. Enabled by
    # default; it only attaches exploit-probability to CVEs we already track.
    sources["epss"] = _source(
        "epss", default_enabled="true",
        base_url="https://api.first.org/data/v1/epss",
        rate=0.8, concurrency=1, timeout=global_timeout, backfill=1,
    )

    ai = AIConfig(
        enabled=_bool("CVE_AI_ENABLED", "true"),
        prefer_router=_bool("CVE_AI_PREFER_ROUTER", "true"),
        language=raw("CVE_DEFAULT_LANGUAGE", "th") or "th",
        summary_max_chars=min(
            env_int("CVE_AI_SUMMARY_MAX_CHARS", 1400), MAX_AI_SUMMARY_CHARS),
        cache_ttl=env_int("CVE_AI_CACHE_TTL", 86400),
        max_repair_attempts=env_int("CVE_AI_MAX_REPAIR", 1),
        max_input_chars=env_int("CVE_AI_MAX_INPUT_CHARS", 12000),
        temperature=(
            env_float("CVE_AI_TEMPERATURE", 0.2)
            if raw("CVE_AI_TEMPERATURE", "") else 0.2
        ),
    )

    admin_topic_raw = env_int("CVE_ALERT_ADMIN_TOPIC_ID", 0)
    alerts = AlertConfig(
        enabled=_bool("CVE_ALERTS_ENABLED", "true"),
        min_cvss=env_float("CVE_ALERT_MIN_CVSS", 0.0),
        min_severity=(raw("CVE_ALERT_MIN_SEVERITY", "MEDIUM") or "MEDIUM").upper(),
        send_rate_per_sec=env_float("CVE_ALERT_SEND_RATE", 0.7),
        send_delay=env_float("CVE_ALERT_SEND_DELAY", 1.2),
        max_per_cycle=env_int("CVE_ALERT_MAX_PER_CYCLE", 25),
        max_send_retries=env_int("CVE_ALERT_MAX_SEND_RETRIES", 4),
        admin_chat_id=env_int("CVE_ALERT_ADMIN_CHAT_ID", 0),
        admin_topic_id=admin_topic_raw or None,
    )

    retention = RetentionConfig(
        raw_days=env_int("CVE_RETENTION_RAW_DAYS", 180),
        ai_summary_days=env_int("CVE_RETENTION_AI_DAYS", 365),
        event_days=env_int("CVE_RETENTION_EVENT_DAYS", 365),
        audit_days=env_int("CVE_RETENTION_AUDIT_DAYS", 730),
        notification_days=env_int("CVE_RETENTION_NOTIFICATION_DAYS", 365),
    )

    max_bytes = min(
        env_int("CVE_MAX_RESPONSE_BYTES", 32 * 1024 * 1024),
        ABSOLUTE_MAX_RESPONSE_BYTES,
    )

    return CVETrackerConfig(
        enabled=enabled,
        db_path=db_path,
        poll_interval=max(30, env_int("CVE_POLL_INTERVAL", 300)),
        max_concurrent_requests=max(1, global_concurrency),
        request_timeout=global_timeout,
        max_retries=env_float("CVE_MAX_RETRIES", 4),
        retry_base_delay=env_float("CVE_RETRY_BASE_DELAY", 2.0),
        retry_max_delay=env_float("CVE_RETRY_MAX_DELAY", 60.0),
        cache_ttl=env_int("CVE_CACHE_TTL", 900),
        max_response_bytes=max_bytes,
        user_agent=raw(
            "CVE_USER_AGENT",
            "SombraGuardian-CVETracker/1.0 (+defensive-monitoring)",
        ),
        sources=sources,
        ai=ai,
        alerts=alerts,
        retention=retention,
    )


# Convenience for the alert filter: severity gate as an ordered list.
def severities_at_or_above(min_severity: str) -> List[str]:
    order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    try:
        idx = order.index((min_severity or "MEDIUM").upper())
    except ValueError:
        idx = order.index("MEDIUM")
    return order[idx:]
