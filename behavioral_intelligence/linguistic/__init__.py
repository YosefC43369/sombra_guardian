"""
behavioral_intelligence.linguistic — language and text intelligence.

Detects the script and language of public text, tracks language use and
code-switching over time, extracts salient keywords (TF-IDF), recurring phrases
(n-grams) and hashtags, surfaces specialised terminology/identifiers, and offers
character-level transliteration comparison. Everything describes observable
language *use*; nationality, ethnicity and first language are never inferred.
"""

from . import (script_detector, language_detector, language_switching,
               keyword_engine, phrase_engine, hashtag_engine, terminology,
               transliteration)
from .language_detector import detect as detect_language_full, detect_language
from .keyword_engine import extract_keywords, tokenize
from .phrase_engine import extract_phrases
from .hashtag_engine import extract_hashtags
from .terminology import extract_terminology, TerminologyResult

__all__ = [
    "script_detector", "language_detector", "language_switching",
    "keyword_engine", "phrase_engine", "hashtag_engine", "terminology",
    "transliteration",
    "detect_language_full", "detect_language", "extract_keywords", "tokenize",
    "extract_phrases", "extract_hashtags", "extract_terminology",
    "TerminologyResult",
]
