"""
config.py — the single place that resolves AI provider configuration.

Why this module exists
----------------------
gemini.py talks to OpenAI: it constructs `AsyncOpenAI(...)` with no
base_url override, and its model defaults are GPT model names. The module
filename and several of its constants still say "Gemini" for historical
reasons, and the .env file that shipped with the repository set
GEMINI_API_KEY / GEMINI_MODEL — names the code never read. The result was
that every AI path logged "GPT_API_KEY is not set" and returned its
fallback message, so /imagine, mention replies, the spam classifier and
news AI summaries were all silently inactive on a deployment that looked
correctly configured.

Rather than rename environment variables and break running deployments,
this module defines one canonical name per setting and an explicit,
ordered fallback chain. A legacy name still works, and using one emits a
single warning naming the canonical replacement.

Scope
-----
AI provider configuration only. Modules with unambiguous, single-name
settings (news.py, github_repo.py, repository_sandbox.py, chain.py,
quota.py, search.py, scrape.py, coordinator.py) keep their own
os.getenv() calls; centralising those would be churn with no defect to
fix. ENV_REGISTRY below documents them so .env.example can be checked
against the code.

Imports stdlib only, so any module can import it without creating a
cycle. Values are read at call time, never at import time, because
app.py calls load_dotenv() after its import block.
"""

import logging
import os
from typing import Dict, List, NamedTuple, Optional

logger = logging.getLogger("modbot.config")

# ---------------- Defaults ----------------

DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_IMAGE_MODEL = "gpt-image-2"

# ---------------- Canonical names and their accepted fallbacks ----------------
# First entry is canonical. Later entries are accepted for compatibility
# and warn once when used.

API_KEY_NAMES: List[str] = ["GPT_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]
MODEL_NAMES: List[str] = ["GPT_MODEL", "OPENAI_MODEL", "GEMINI_MODEL"]
IMAGE_MODEL_NAMES: List[str] = ["GPT_IMAGE_MODEL", "OPENAI_IMAGE_MODEL"]
CLASSIFIER_MODEL_NAMES: List[str] = ["GPT_CLASSIFIER_MODEL", "GEMINI_CLASSIFIER_MODEL"]

_warned: set = set()


def _warn_once(used: str, canonical: str) -> None:
    if used in _warned:
        return
    _warned.add(used)
    logger.warning(
        "CONFIG: %s is deprecated; use %s instead. Both work for now.",
        used, canonical,
    )
    
    
def _resolve(names: List[str], default: Optional[str] = None) -> Optional[str]:
    """First non-empty value among `names`, warning if it was not the
    canonical (first) name. Never logs the value itself — these can be
    secrets."""
    canonical = names[0]
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            if name != canonical:
                _warn_once(name, canonical)
            return value.strip()
    return default
    

def resolve_api_key() -> Optional[str]:
    """The AI provider API key, or None if no accepted name is set."""
    return _resolve(API_KEY_NAMES)
    
    
def resolve_model() -> str:
    return _resolve(MODEL_NAMES, DEFAULT_MODEL)
    
    
def resolve_classifier_model() -> str:
    """The classifier falls back to the general chat model, matching the
    behaviour gemini.classify_spam() already had."""
    return _resolve(CLASSIFIER_MODEL_NAMES) or resolve_model()
    
    
def ai_configured() -> bool:
    """True when optional AI features can run. Core moderation, ledger and
    bug-bounty commands do not depend on this."""
    return resolve_api_key() is not None
    
    
def api_key_source() -> Optional[str]:
    """Which environment variable name supplied the key, for startup
    logging and diagnostics. Returns the NAME, never the value."""
    for name in API_KEY_NAMES:
        value = os.getenv(name)
        if value and value.strip():
            return name
        return None
        
        
def log_startup_summary() -> None:
    """One line at startup so an operator learns AI is unconfigured then,
    rather than when a user first runs /imagine. Logs variable names and
    model names only — never a key, never a fragment of one."""
    if ai_configured():
        logger.info(
            "CONFIG: AI enabled (key from %s, model=%s, image=%s)",
            api_key_source(), resolve_model(), resolve_image_model(),
        )
    else:
        logger.warning(
            "CONFIG: AI disabled — none of %s is set. The bot runs "
            "normally; AI features will return a configuration message.",
            ", ".join(API_KEY_NAMES),
        )
        
        
# ---------------- Environment variable registry ----------------

class EnvVar(NamedTuple):
    name: str
    module: str
    purpose: str
    required: bool
    default: str


ENV_REGISTRY: Dict[str, EnvVar] = {v.name: v for v in [
    # Telegram — the only genuinely required setting
    EnvVar("BOT_TOKEN", "app.py", "Telegram bot token", True,
           "none — app.py exits if unset"),

    # AI provider (optional; canonical names first)
    EnvVar("GPT_API_KEY", "config.py/gemini.py", "AI provider API key", False,
           "unset — AI features return a configuration message"),
    EnvVar("GPT_MODEL", "config.py/gemini.py", "chat model", False, DEFAULT_MODEL),
    EnvVar("GPT_IMAGE_MODEL", "config.py/gemini.py", "image model", False,
           DEFAULT_IMAGE_MODEL),
    EnvVar("GPT_CLASSIFIER_MODEL", "config.py/gemini.py",
           "spam-classifier model", False, "falls back to GPT_MODEL"),

    # Quotas
    EnvVar("AI_MEMBER_DAILY_LIMIT", "quota.py", "per-member daily AI calls",
           False, "10"),
    EnvVar("AI_ADMIN_DAILY_LIMIT", "quota.py", "per-admin daily AI calls",
           False, "0 (unlimited)"),
    EnvVar("AI_CLASSIFIER_DAILY_LIMIT", "quota.py",
           "chat-wide daily classifier calls", False, "300"),

    # News background service
    EnvVar("NEWS_CHECK_INTERVAL", "news.py", "seconds between RSS polls",
           False, "module default"),
    EnvVar("NEWS_HTTP_TIMEOUT", "news.py", "RSS/article fetch timeout",
           False, "module default"),
    EnvVar("NEWS_MAX_ITEMS_PER_CYCLE", "news.py", "items posted per cycle",
           False, "module default"),
    EnvVar("NEWS_SEND_BACKLOG_ON_FIRST_RUN", "news.py",
           "post existing items on first run", False, "module default"),
    EnvVar("NEWS_AI_SUMMARY_MAX_CHARS", "news.py", "AI summary length cap",
           False, "module default"),
    EnvVar("NEWS_ARTICLE_MAX_CHARS", "news.py", "article text cap", False,
           "module default"),
    EnvVar("NEWS_RSS_SUMMARY_MIN_CHARS", "news.py",
           "min RSS summary before fetching the page", False, "module default"),
    EnvVar("NEWS_FEED_URL_HACKERNEWS", "news.py", "feed URL", False, "module default"),
    EnvVar("NEWS_PAGE_URL_HACKERNEWS", "news.py", "site URL", False, "module default"),
    EnvVar("NEWS_CHAT_ID_HACKERNEWS", "news.py", "destination chat", False, "unset"),
    EnvVar("NEWS_TOPIC_ID_HACKERNEWS", "news.py", "destination topic", False, "unset"),
    EnvVar("NEWS_FEED_URL_KREBSONSECURITY", "news.py", "feed URL", False,
           "module default"),
    EnvVar("NEWS_PAGE_URL_KREBSONSECURITY", "news.py", "site URL", False,
           "module default"),
    EnvVar("NEWS_CHAT_ID_KREBSONSECURITY", "news.py", "destination chat", False,
           "unset"),
    EnvVar("NEWS_TOPIC_ID_KREBSONSECURITY", "news.py", "destination topic", False,
           "unset"),

    # Tor-backed lookups used by /identity and /corporate
    EnvVar("TOR_SOCKS_HOST", "search.py/scrape.py", "Tor SOCKS host", False,
           "127.0.0.1"),
    EnvVar("TOR_SOCKS_PORT", "search.py/scrape.py", "Tor SOCKS port", False, "9050"),
    EnvVar("TOR_GATEWAY_SUFFIXES", "search.py", "onion gateway suffixes", False,
           ".ly,.ps"),

    # Coordinator
    EnvVar("COORDINATOR_MAX_WORKERS", "coordinator.py", "concurrent workers",
           False, "module default"),

    # Repository test sandbox (disabled by default)
    EnvVar("REPO_TEST_EXECUTION_ENABLED", "repository_sandbox.py",
           "master safety switch", False, "off"),
    EnvVar("REPO_TEST_TIMEOUT_SECONDS", "repository_sandbox.py",
           "wall-clock cap", False, "module default"),
    EnvVar("REPO_TEST_MEMORY_LIMIT_BYTES", "repository_sandbox.py",
           "RLIMIT_AS ceiling", False, "module default"),
    EnvVar("REPO_TEST_MAX_PROCESSES", "repository_sandbox.py",
           "RLIMIT_NPROC ceiling", False, "module default"),
    EnvVar("REPO_TEST_MAX_OUTPUT_BYTES", "repository_sandbox.py",
           "captured output cap", False, "module default"),
    EnvVar("REPO_MAX_CONCURRENT_TEST_RUNS", "repository_sandbox.py",
           "concurrent sandboxed runs", False, "module default"),

    # Blockchain anchoring (optional; bot runs without it)
    EnvVar("CHAIN_ENABLED", "blockchain/src/chain.py", "enable anchoring",
           False, "off"),
    EnvVar("CHAIN_BINARY", "blockchain/src/chain.py", "path to sombra-chain",
           False, "module default"),
    EnvVar("CHAIN_TIMEOUT", "blockchain/src/chain.py", "subprocess timeout",
           False, "module default"),
    EnvVar("CHAIN_ANCHOR_INTERVAL", "blockchain/src/chain.py",
           "seconds between anchors", False, "module default"),
    EnvVar("CHAIN_MAX_TX_PER_BLOCK", "blockchain/src/chain.py",
           "transactions per block", False, "module default"),
    EnvVar("CHAIN_STARTUP_DELAY", "blockchain/src/chain.py",
           "delay before first anchor", False, "module default"),
]}


def required_names() -> List[str]:
    return [v.name for v in ENV_REGISTRY.values() if v.required]


def optional_names() -> List[str]:
    return [v.name for v in ENV_REGISTRY.values() if not v.required]