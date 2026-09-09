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