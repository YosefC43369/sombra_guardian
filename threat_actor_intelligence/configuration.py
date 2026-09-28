"""
threat_actor_intelligence.configuration — resolved, typed settings.

Follows the repo config discipline (see ``config.py`` / ``blueteam.config`` /
``behavioral_intelligence.configuration``): stdlib only, values read from the
environment at call time (never at import — ``app.py`` loads the .env after its
import block), never logs a secret, and every setting has a safe default so the
analytical core runs with zero configuration.

ALL provider API keys come from the environment. None are hardcoded. A provider
with no key configured is simply skipped by the orchestrator (it is not an
error), so the engine degrades gracefully from "MITRE + local feeds only" up to
"every configured public source".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


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


def _env_list(name: str, default: List[str]) -> List[str]:
    v = _env(name)
    if not v:
        return list(default)
    return [p.strip() for p in v.split(",") if p.strip()]


# Default public feeds (RSS/Atom). All are widely-published security advisory /
# research feeds. Overridable via TAI_RSS_FEEDS (comma-separated).
DEFAULT_RSS_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/news.xml",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://research.checkpoint.com/feed/",
]

# Default public TAXII 2.1 roots. MITRE ATT&CK is served from a well-known root.
DEFAULT_TAXII_ROOTS = [
    "https://attack-taxii.mitre.org/api/v21/",
]


@dataclass
class ProviderConfig:
    """Per-provider knobs: whether it is enabled, its env var for the API key,
    and its polite rate limit. The key itself is resolved at call time and never
    stored on the object."""
    name: str
    enabled: bool = True
    key_env: str = ""
    rate_limit_per_min: float = 30.0
    timeout_seconds: float = 20.0
    base_url: str = ""

    def api_key(self) -> Optional[str]:
        return _env(self.key_env) if self.key_env else None

    def is_available(self) -> bool:
        if not self.enabled:
            return False
        if self.key_env and not self.api_key():
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled,
                "key_env": self.key_env, "has_key": bool(self.api_key())
                if self.key_env else True,
                "rate_limit_per_min": self.rate_limit_per_min,
                "timeout_seconds": self.timeout_seconds, "base_url": self.base_url}


@dataclass
class TAIConfig:
    # storage
    db_path: str = "threat_actor_intelligence.db"
    cache_dir: str = ".tai_cache"
    cache_ttl_seconds: int = 21600          # 6h default disk-cache TTL

    # ingestion / performance
    stream_batch_size: int = 500
    http_timeout_seconds: float = 20.0
    max_report_summary_chars: int = 2000
    default_rss_feeds: List[str] = field(default_factory=lambda: list(DEFAULT_RSS_FEEDS))
    taxii_roots: List[str] = field(default_factory=lambda: list(DEFAULT_TAXII_ROOTS))
    user_agent: str = "SombraGuardian-TAI/1.0 (+public-CTI-analysis)"
    respect_robots: bool = True

    # correlation thresholds
    alias_match_threshold: float = 0.86     # fuzzy alias similarity to *suggest*
    min_overlap_signals: int = 1            # infra overlap signals to link
    correlation_min_confidence: float = 0.30

    # scheduling
    incremental_only: bool = True
    poll_interval_seconds: int = 3600

    # providers
    providers: Dict[str, ProviderConfig] = field(default_factory=dict)

    # integration toggles
    use_geo_osint: bool = True
    use_entity_fusion: bool = True
    use_evidence_ledger: bool = True

    def provider(self, name: str) -> ProviderConfig:
        return self.providers.get(name, ProviderConfig(name=name, enabled=False))

    def available_providers(self) -> List[str]:
        return sorted(n for n, p in self.providers.items() if p.is_available())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["providers"] = {n: p.to_dict() for n, p in self.providers.items()}
        return d


def _default_providers() -> Dict[str, ProviderConfig]:
    """Provider registry. Public metadata sources; the ones needing a key are
    only 'available' when the key is present in the environment."""
    specs = [
        # name,             key_env,                 rate,  base_url
        ("mitre_attack",    "",                      60,    "https://raw.githubusercontent.com/mitre/cti"),
        ("cisa",            "",                      30,    "https://www.cisa.gov"),
        ("cisa_kev",        "",                      30,    "https://www.cisa.gov/sites/default/files/feeds"),
        ("nvd",             "NVD_API_KEY",           50,    "https://services.nvd.nist.gov/rest/json"),
        ("otx",             "OTX_API_KEY",           30,    "https://otx.alienvault.com/api/v1"),
        ("urlhaus",         "",                      30,    "https://urlhaus-api.abuse.ch/v1"),
        ("malwarebazaar",   "MALWAREBAZAAR_API_KEY", 30,    "https://mb-api.abuse.ch/api/v1"),
        ("threatfox",       "",                      30,    "https://threatfox-api.abuse.ch/api/v1"),
        ("github",          "GITHUB_TOKEN",          40,    "https://api.github.com"),
        ("virustotal",      "VIRUSTOTAL_API_KEY",    4,     "https://www.virustotal.com/api/v3"),
        ("abuseipdb",       "ABUSEIPDB_API_KEY",     20,    "https://api.abuseipdb.com/api/v2"),
        ("rss",             "",                      60,    ""),
        ("taxii",           "",                      30,    ""),
        ("stix",            "",                      60,    ""),
        ("vendor",          "",                      30,    ""),
    ]
    out: Dict[str, ProviderConfig] = {}
    for name, key_env, rate, base in specs:
        out[name] = ProviderConfig(
            name=name, enabled=_env_bool(f"TAI_{name.upper()}_ENABLED", True),
            key_env=key_env,
            rate_limit_per_min=_env_float(f"TAI_{name.upper()}_RATE", float(rate)),
            timeout_seconds=_env_float("TAI_HTTP_TIMEOUT", 20.0), base_url=base)
    return out


def get_config() -> TAIConfig:
    """Resolve configuration from the environment. Call at runtime, not import."""
    return TAIConfig(
        db_path=_env("TAI_DB_PATH", "threat_actor_intelligence.db"),
        cache_dir=_env("TAI_CACHE_DIR", ".tai_cache"),
        cache_ttl_seconds=_env_int("TAI_CACHE_TTL", 21600),
        stream_batch_size=_env_int("TAI_STREAM_BATCH", 500),
        http_timeout_seconds=_env_float("TAI_HTTP_TIMEOUT", 20.0),
        max_report_summary_chars=_env_int("TAI_MAX_SUMMARY", 2000),
        default_rss_feeds=_env_list("TAI_RSS_FEEDS", DEFAULT_RSS_FEEDS),
        taxii_roots=_env_list("TAI_TAXII_ROOTS", DEFAULT_TAXII_ROOTS),
        user_agent=_env("TAI_USER_AGENT", "SombraGuardian-TAI/1.0 (+public-CTI-analysis)"),
        respect_robots=_env_bool("TAI_RESPECT_ROBOTS", True),
        alias_match_threshold=_env_float("TAI_ALIAS_THRESHOLD", 0.86),
        min_overlap_signals=_env_int("TAI_MIN_OVERLAP", 1),
        correlation_min_confidence=_env_float("TAI_CORR_MIN_CONF", 0.30),
        incremental_only=_env_bool("TAI_INCREMENTAL_ONLY", True),
        poll_interval_seconds=_env_int("TAI_POLL_INTERVAL", 3600),
        providers=_default_providers(),
        use_geo_osint=_env_bool("TAI_USE_GEO_OSINT", True),
        use_entity_fusion=_env_bool("TAI_USE_ENTITY_FUSION", True),
        use_evidence_ledger=_env_bool("TAI_USE_EVIDENCE_LEDGER", True),
    )


__all__ = ["TAIConfig", "ProviderConfig", "get_config", "DEFAULT_RSS_FEEDS",
           "DEFAULT_TAXII_ROOTS"]
