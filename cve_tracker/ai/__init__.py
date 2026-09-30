"""
cve_tracker.ai — the AI summarization/translation pipeline.

Reuses the host project's AI (``ai_router`` / ``gemini``) through
:class:`AIProviderAdapter`; the subsystem is provider-agnostic. The summarizer
turns structured facts into a validated Thai summary, with a deterministic
fallback so AI downtime never stops CVE publishing (rules §13–§16, §33).
"""

from .adapter import AIProviderAdapter, AIResult
from .summarizer import CVESummarizer
from .translator import Translator
from .cache import AISummaryCache
from . import prompt_builder, validator, analyzer

__all__ = [
    "AIProviderAdapter", "AIResult", "CVESummarizer", "Translator",
    "AISummaryCache", "prompt_builder", "validator", "analyzer",
]
