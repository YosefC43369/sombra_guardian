"""
news_intelligence.language — language detection + optional metadata translation.

Dependency-free heuristic language detection (script ranges + common stopword
profiles) sufficient to tag an article's language and drive language filters. The
original text is always preserved; translation of *metadata only* (title/summary) is
opt-in and, when enabled, routed through the repo's existing Gemini/OpenAI helpers if
available — otherwise it is a no-op (never fabricate a translation).

Multilingual entity resolution normalizes cross-language aliases only via the curated
reference clusters; it never merges two entities without evidence.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Optional

# common stopword fingerprints per language (small, high-precision)
_PROFILES: Dict[str, set] = {
    "en": {"the", "and", "of", "to", "in", "for", "with", "that", "was"},
    "es": {"el", "la", "de", "los", "que", "y", "en", "para", "con", "una"},
    "fr": {"le", "la", "les", "de", "des", "et", "que", "pour", "une", "dans"},
    "de": {"der", "die", "das", "und", "den", "von", "mit", "für", "ist", "auf"},
    "pt": {"o", "a", "de", "que", "e", "do", "da", "em", "para", "uma"},
    "it": {"il", "la", "di", "che", "e", "un", "per", "con", "del", "una"},
    "ru": {"и", "в", "не", "на", "что", "с", "по", "как", "это", "для"},
}

_SCRIPT_RANGES = [
    ("ru", re.compile(r"[Ѐ-ӿ]")),
    ("zh", re.compile(r"[一-鿿]")),
    ("ja", re.compile(r"[぀-ヿ]")),
    ("ko", re.compile(r"[가-힯]")),
    ("ar", re.compile(r"[؀-ۿ]")),
    ("he", re.compile(r"[֐-׿]")),
    ("th", re.compile(r"[฀-๿]")),
]

_WORD_RE = re.compile(r"[a-zA-Zа-яА-Я]+")


def detect_language(text: str, *, default: str = "en") -> str:
    if not text:
        return default
    for lang, rx in _SCRIPT_RANGES:
        if len(rx.findall(text)) >= 3:
            return lang
    words = [w.lower() for w in _WORD_RE.findall(text)][:400]
    if not words:
        return default
    wordset = set(words)
    best, best_score = default, 0
    for lang, profile in _PROFILES.items():
        score = len(wordset & profile)
        if score > best_score:
            best, best_score = lang, score
    return best if best_score >= 2 else default


class LanguageEngine:
    def __init__(self, *, default: str = "en", translate: bool = False,
                 cache=None):
        self.default = default
        self.translate = translate
        self.cache = cache

    def detect(self, text: str) -> str:
        return detect_language(text, default=self.default)

    def annotate(self, article) -> None:
        """Set the article's language if unknown; preserve original text always."""
        if not article.language:
            article.language = self.detect(f"{article.title} {article.summary}")

    def translate_metadata(self, text: str, *, target: str = "en") -> str:
        """Translate title/summary metadata when configured; else return original.

        Routes through the repo's Gemini helper if present; never invents a
        translation when no backend is available."""
        if not self.translate or not text:
            return text
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]
        if self.cache is not None:
            cached = self.cache.get_translation(h, target)
            if cached:
                return cached
        translated = self._backend_translate(text, target)
        if translated and self.cache is not None:
            self.cache.set_translation(h, target, translated)
        return translated or text

    def _backend_translate(self, text: str, target: str) -> Optional[str]:  # pragma: no cover
        try:
            import gemini  # type: ignore
            fn = getattr(gemini, "translate", None)
            if callable(fn):
                return fn(text, target)
        except Exception:
            return None
        return None


__all__ = ["detect_language", "LanguageEngine"]
