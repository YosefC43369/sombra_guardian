"""
news_intelligence.configuration — resolved, typed settings + default source registry.

Follows the repo config discipline (see ``config.py`` / ``blueteam.config`` /
``threat_actor_intelligence.configuration``): stdlib only, values read from the
environment at call time (never at import — ``app.py`` loads the .env after its
import block), never logs a secret, every setting has a safe default so the
analytical core runs with zero configuration.

Ships a curated registry of *publicly published* security news/advisory feeds
(vendor blogs, CERTs, government advisories, research blogs, GitHub advisories).
Overridable/extendable via ``NI_EXTRA_FEEDS`` (comma-separated URLs) and per-source
enable flags. Provider API keys come only from the environment; a provider with no
key is skipped by the orchestrator, so the engine degrades gracefully from "local
RSS only" to "every configured public source".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .models.source import NewsSource, SourceCategory, ReliabilityClass


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


# --- default public source registry ---------------------------------------- #
# (name, category, reliability_class, country, rss_url)
_C = SourceCategory
_R = ReliabilityClass
DEFAULT_SOURCE_SPECS = [
    ("CISA Advisories", _C.GOVERNMENT_ADVISORY, _R.OFFICIAL_GOVERNMENT, "US",
     "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("CISA News", _C.GOVERNMENT_ADVISORY, _R.OFFICIAL_GOVERNMENT, "US",
     "https://www.cisa.gov/news.xml"),
    ("US-CERT Alerts", _C.CERT, _R.CERT, "US",
     "https://www.cisa.gov/uscert/ncas/alerts.xml"),
    ("NCSC UK News", _C.GOVERNMENT_ADVISORY, _R.OFFICIAL_GOVERNMENT, "UK",
     "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),
    ("The Hacker News", _C.NEWS_ORGANIZATION, _R.NEWS_OUTLET, "",
     "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", _C.NEWS_ORGANIZATION, _R.NEWS_OUTLET, "",
     "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", _C.RESEARCH_BLOG, _R.INDEPENDENT_RESEARCHER, "US",
     "https://krebsonsecurity.com/feed/"),
    ("Unit 42", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "US",
     "https://unit42.paloaltonetworks.com/feed/"),
    ("Check Point Research", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "IL",
     "https://research.checkpoint.com/feed/"),
    ("Google TAG / Threat Analysis", _C.VENDOR_SECURITY_BLOG, _R.VENDOR_RESEARCH,
     "US", "https://blog.google/threat-analysis-group/rss/"),
    ("Microsoft Security Blog", _C.VENDOR_SECURITY_BLOG, _R.VENDOR_RESEARCH, "US",
     "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Cisco Talos", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "US",
     "https://blog.talosintelligence.com/rss/"),
    ("Mandiant", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "US",
     "https://www.mandiant.com/resources/blog/rss.xml"),
    ("SentinelOne Labs", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "US",
     "https://www.sentinelone.com/labs/feed/"),
    ("Securelist (Kaspersky)", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "RU",
     "https://securelist.com/feed/"),
    ("WeLiveSecurity (ESET)", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "SK",
     "https://www.welivesecurity.com/en/rss/feed/"),
    ("Sophos News", _C.VENDOR_SECURITY_BLOG, _R.VENDOR_RESEARCH, "UK",
     "https://news.sophos.com/en-us/feed/"),
    ("Recorded Future", _C.THREAT_INTEL_VENDOR, _R.VENDOR_RESEARCH, "US",
     "https://www.recordedfuture.com/feed"),
    ("Project Zero", _C.RESEARCH_BLOG, _R.VENDOR_RESEARCH, "US",
     "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("GitHub Security Advisories", _C.GITHUB_SECURITY_FEED, _R.COMMUNITY_BLOG, "",
     "https://github.com/advisories.atom"),
    ("SANS ISC Diary", _C.RESEARCH_BLOG, _R.INDEPENDENT_RESEARCHER, "US",
     "https://isc.sans.edu/rssfeed_full.xml"),
]


def default_sources() -> List[NewsSource]:
    out: List[NewsSource] = []
    for name, cat, rel, country, url in DEFAULT_SOURCE_SPECS:
        env_name = "NI_SRC_" + "".join(c if c.isalnum() else "_"
                                       for c in name.upper())
        enabled = _env_bool(env_name + "_ENABLED", True)
        out.append(NewsSource(name=name, category=cat, reliability_class=rel,
                              country=country, rss_url=url, enabled=enabled,
                              update_frequency=_env_int("NI_POLL_INTERVAL", 3600)))
    for extra in _env_list("NI_EXTRA_FEEDS", []):
        out.append(NewsSource(name=extra, category=SourceCategory.NEWS_ORGANIZATION,
                              reliability_class=ReliabilityClass.UNKNOWN,
                              rss_url=extra))
    return out


@dataclass
class ProviderConfig:
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
                "key_env": self.key_env,
                "has_key": bool(self.api_key()) if self.key_env else True,
                "rate_limit_per_min": self.rate_limit_per_min,
                "timeout_seconds": self.timeout_seconds, "base_url": self.base_url}


def _default_providers() -> Dict[str, ProviderConfig]:
    specs = [
        ("rss", "", 60, ""),
        ("atom", "", 60, ""),
        ("json_feed", "", 60, ""),
        ("vendor", "", 30, ""),
        ("github", "GITHUB_TOKEN", 40, "https://api.github.com"),
        ("cisa", "", 30, "https://www.cisa.gov"),
        ("cisa_kev", "", 30,
         "https://www.cisa.gov/sites/default/files/feeds"),
        ("cert", "", 30, ""),
        ("nvd", "NVD_API_KEY", 50, "https://services.nvd.nist.gov/rest/json"),
        ("exploit_blog", "", 30, ""),
        ("podcast", "", 30, ""),
    ]
    out: Dict[str, ProviderConfig] = {}
    for name, key_env, rate, base in specs:
        out[name] = ProviderConfig(
            name=name, enabled=_env_bool(f"NI_{name.upper()}_ENABLED", True),
            key_env=key_env,
            rate_limit_per_min=_env_float(f"NI_{name.upper()}_RATE", float(rate)),
            timeout_seconds=_env_float("NI_HTTP_TIMEOUT", 20.0), base_url=base)
    return out


@dataclass
class NewsIntelConfig:
    # storage
    db_path: str = "news_intelligence.db"
    cache_dir: str = ".ni_cache"
    cache_ttl_seconds: int = 21600

    # ingestion / performance
    stream_batch_size: int = 500
    http_timeout_seconds: float = 20.0
    max_body_chars: int = 20000
    max_summary_chars: int = 2000
    user_agent: str = "SombraGuardian-NI/2.0 (+public-news-intelligence)"
    respect_robots: bool = True
    poll_interval_seconds: int = 3600
    incremental_only: bool = True

    # dedup / clustering thresholds
    simhash_hamming_threshold: int = 3       # <= this = near-duplicate
    minhash_jaccard_threshold: float = 0.7
    tfidf_similarity_threshold: float = 0.55
    event_window_hours: int = 72             # articles within this window can cluster
    cluster_min_shared_signals: int = 1

    # correlation / trend thresholds
    correlation_min_confidence: float = 0.30
    trend_min_sample: int = 3
    trend_window_days: int = 7

    # language
    default_language: str = "en"
    translate_metadata: bool = False

    # providers / sources
    providers: Dict[str, ProviderConfig] = field(default_factory=dict)

    # integration toggles
    use_threat_actor_intel: bool = True
    use_entity_fusion: bool = True
    use_web_footprint: bool = True
    use_geo_osint: bool = True
    use_behavioral_intel: bool = True

    def provider(self, name: str) -> ProviderConfig:
        return self.providers.get(name, ProviderConfig(name=name, enabled=False))

    def available_providers(self) -> List[str]:
        return sorted(n for n, p in self.providers.items() if p.is_available())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["providers"] = {n: p.to_dict() for n, p in self.providers.items()}
        return d


def get_config() -> NewsIntelConfig:
    """Resolve configuration from the environment. Call at runtime, not import."""
    return NewsIntelConfig(
        db_path=_env("NI_DB_PATH", "news_intelligence.db"),
        cache_dir=_env("NI_CACHE_DIR", ".ni_cache"),
        cache_ttl_seconds=_env_int("NI_CACHE_TTL", 21600),
        stream_batch_size=_env_int("NI_STREAM_BATCH", 500),
        http_timeout_seconds=_env_float("NI_HTTP_TIMEOUT", 20.0),
        max_body_chars=_env_int("NI_MAX_BODY", 20000),
        max_summary_chars=_env_int("NI_MAX_SUMMARY", 2000),
        user_agent=_env("NI_USER_AGENT",
                        "SombraGuardian-NI/2.0 (+public-news-intelligence)"),
        respect_robots=_env_bool("NI_RESPECT_ROBOTS", True),
        poll_interval_seconds=_env_int("NI_POLL_INTERVAL", 3600),
        incremental_only=_env_bool("NI_INCREMENTAL_ONLY", True),
        simhash_hamming_threshold=_env_int("NI_SIMHASH_HAMMING", 3),
        minhash_jaccard_threshold=_env_float("NI_MINHASH_JACCARD", 0.7),
        tfidf_similarity_threshold=_env_float("NI_TFIDF_SIM", 0.55),
        event_window_hours=_env_int("NI_EVENT_WINDOW_HOURS", 72),
        cluster_min_shared_signals=_env_int("NI_CLUSTER_MIN_SIGNALS", 1),
        correlation_min_confidence=_env_float("NI_CORR_MIN_CONF", 0.30),
        trend_min_sample=_env_int("NI_TREND_MIN_SAMPLE", 3),
        trend_window_days=_env_int("NI_TREND_WINDOW_DAYS", 7),
        default_language=_env("NI_DEFAULT_LANG", "en"),
        translate_metadata=_env_bool("NI_TRANSLATE_METADATA", False),
        providers=_default_providers(),
        use_threat_actor_intel=_env_bool("NI_USE_TAI", True),
        use_entity_fusion=_env_bool("NI_USE_ENTITY_FUSION", True),
        use_web_footprint=_env_bool("NI_USE_WEB_FOOTPRINT", True),
        use_geo_osint=_env_bool("NI_USE_GEO_OSINT", True),
        use_behavioral_intel=_env_bool("NI_USE_BEHAVIORAL", True),
    )


__all__ = ["NewsIntelConfig", "ProviderConfig", "get_config", "default_sources",
           "DEFAULT_SOURCE_SPECS"]
