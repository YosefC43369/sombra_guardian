"""
behavioral_intelligence.linguistic.language_detector — heuristic language
detection for public text (spec §9).

No external model. Two complementary signals:

  1. Script. Thai/Japanese-kana/Hangul/Arabic/Hebrew/Cyrillic/Devanagari scripts
     map near-deterministically to a language. Han without kana is treated as
     Chinese; Han *with* kana is Japanese.
  2. Stopwords. Latin-script languages (English, Spanish, French, German,
     Portuguese, Indonesian, Vietnamese, Malay) are separated by scoring the
     text against small high-frequency function-word sets.

The result carries a calibrated confidence and the full script breakdown, and
flags mixed-language/script content rather than forcing a single label. The
engine reports language *use*; it never infers nationality or ethnicity (a
standing limitation attached wherever these results feed an assertion).
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..models.language import LanguageDetection
from . import script_detector

# Script → language for scripts that essentially determine the language.
_SCRIPT_LANG = {
    "Thai": "th", "Hangul": "ko", "Arabic": "ar", "Hebrew": "he",
    "Cyrillic": "ru", "Devanagari": "hi", "Greek": "el",
}

# High-frequency function words per Latin-script language. Deliberately small and
# distinctive; scoring is by fraction of tokens that are stopwords of a language.
_STOPWORDS: Dict[str, set] = {
    "en": {"the", "and", "is", "to", "of", "in", "it", "you", "that", "for",
           "on", "with", "this", "are", "was", "have", "not", "but", "we"},
    "es": {"el", "la", "de", "que", "y", "los", "las", "una", "por", "con",
           "para", "es", "un", "no", "se", "su", "lo", "como", "más"},
    "fr": {"le", "la", "les", "de", "et", "un", "une", "que", "pour", "dans",
           "sur", "est", "pas", "ne", "je", "vous", "avec", "au", "des"},
    "de": {"der", "die", "das", "und", "ist", "nicht", "ein", "eine", "mit",
           "auf", "den", "von", "zu", "ich", "wir", "auch", "im", "dem"},
    "pt": {"o", "a", "de", "que", "e", "do", "da", "em", "para", "com", "não",
           "uma", "os", "no", "se", "por", "mais", "as", "dos"},
    "id": {"yang", "di", "dan", "itu", "dengan", "untuk", "tidak", "ini", "dari",
           "dalam", "akan", "pada", "juga", "saya", "kita", "adalah"},
    "ms": {"yang", "dan", "di", "ini", "itu", "dengan", "untuk", "tidak", "adalah",
           "dalam", "akan", "pada", "saya", "kami", "kepada", "atau"},
    "vi": {"và", "của", "là", "không", "có", "được", "một", "những", "cho",
           "này", "trong", "người", "đã", "khi", "để", "với"},
}

_TOKEN_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


def _latin_language(text: str) -> List[Tuple[str, float]]:
    tokens = [t.casefold() for t in _TOKEN_RE.findall(text)]
    if not tokens:
        return [("und", 0.0)]
    n = len(tokens)
    scores: Dict[str, float] = {}
    for lang, words in _STOPWORDS.items():
        hits = sum(1 for t in tokens if t in words)
        if hits:
            scores[lang] = hits / n
    if not scores:
        # Latin letters but no recognised stopwords — likely English-ish or a
        # name/handle; return low-confidence English rather than a false label.
        return [("en", 0.15), ("und", 0.1)]
    ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return ordered


def detect(text: str) -> LanguageDetection:
    """Detect the dominant language of a single piece of text."""
    if not text or not text.strip():
        return LanguageDetection(language="und", confidence=0.0)

    shares = script_detector.script_shares(text)
    result = LanguageDetection(scripts=shares,
                               mixed=script_detector.is_mixed_script(text))
    if not shares:
        result.language = "und"
        return result

    dom_script = max(shares, key=lambda k: shares[k])
    result.script = dom_script

    # Japanese vs Chinese disambiguation: any kana => Japanese.
    if dom_script in ("Han", "Hiragana", "Katakana"):
        has_kana = shares.get("Hiragana", 0) + shares.get("Katakana", 0) > 0
        lang = "ja" if has_kana else "zh"
        result.language = lang
        result.confidence = min(0.98, 0.6 + shares.get(dom_script, 0) * 0.4)
        result.candidates = [(lang, result.confidence)]
        return result

    if dom_script in _SCRIPT_LANG:
        lang = _SCRIPT_LANG[dom_script]
        result.language = lang
        result.confidence = min(0.97, 0.55 + shares[dom_script] * 0.42)
        result.candidates = [(lang, result.confidence)]
        return result

    if dom_script == "Latin":
        cands = _latin_language(text)
        top_lang, top_score = cands[0]
        # confidence blends stopword coverage with a margin over the runner-up
        runner = cands[1][1] if len(cands) > 1 else 0.0
        margin = max(0.0, top_score - runner)
        result.language = top_lang
        result.confidence = min(0.95, 0.35 + top_score * 1.5 + margin)
        result.candidates = cands[:4]
        return result

    # Some other script we classified but don't language-map.
    result.language = "und"
    result.confidence = 0.2
    return result


def detect_language(text: str) -> str:
    """Convenience: just the ISO-639-1 code (or 'und')."""
    return detect(text).language
