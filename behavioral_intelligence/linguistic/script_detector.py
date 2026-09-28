"""
behavioral_intelligence.linguistic.script_detector — Unicode script detection.

Classifies each character of a text into a writing system by codepoint range and
returns the share of each script present. This is the primitive under language
detection (a Thai script strongly implies Thai; mixed scripts flag code-switching
or transliteration). Standard library only — no ICU, no external data — so it
runs in the pure analytical core.

Script coverage matches the languages the spec calls out (§9): Latin, Thai,
Han (Chinese/Japanese Kanji), Hiragana, Katakana, Hangul, Arabic, Hebrew,
Cyrillic, plus Devanagari and Greek for completeness.
"""

from __future__ import annotations

import unicodedata
from typing import Dict, List, Tuple

# Ordered (name, (lo, hi)) codepoint ranges. First matching range wins. CJK is
# split so Japanese kana are distinguishable from Han ideographs.
_RANGES: List[Tuple[str, Tuple[int, int]]] = [
    ("Latin", (0x0041, 0x024F)),
    ("Latin", (0x1E00, 0x1EFF)),        # Latin Extended Additional (Vietnamese)
    ("Greek", (0x0370, 0x03FF)),
    ("Cyrillic", (0x0400, 0x04FF)),
    ("Hebrew", (0x0590, 0x05FF)),
    ("Arabic", (0x0600, 0x06FF)),
    ("Arabic", (0x0750, 0x077F)),
    ("Devanagari", (0x0900, 0x097F)),
    ("Thai", (0x0E00, 0x0E7F)),
    ("Hangul", (0x1100, 0x11FF)),       # Jamo
    ("Hangul", (0xAC00, 0xD7A3)),       # Hangul syllables
    ("Hiragana", (0x3040, 0x309F)),
    ("Katakana", (0x30A0, 0x30FF)),
    ("Han", (0x3400, 0x4DBF)),          # CJK Ext A
    ("Han", (0x4E00, 0x9FFF)),          # CJK Unified
    ("Han", (0xF900, 0xFAFF)),          # CJK Compatibility
]


def _script_of(ch: str) -> str:
    cp = ord(ch)
    for name, (lo, hi) in _RANGES:
        if lo <= cp <= hi:
            return name
    return ""


def script_shares(text: str) -> Dict[str, float]:
    """Return {script_name: share} over the *letter* characters of the text
    (digits, punctuation and whitespace are ignored). Empty for no letters."""
    counts: Dict[str, int] = {}
    total = 0
    for ch in text:
        if not (ch.isalpha() or unicodedata.category(ch).startswith("L")):
            continue
        name = _script_of(ch)
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
        total += 1
    if total == 0:
        return {}
    return {k: v / total for k, v in counts.items()}


def dominant_script(text: str) -> str:
    shares = script_shares(text)
    if not shares:
        return ""
    return max(shares, key=lambda k: shares[k])


def is_mixed_script(text: str, *, threshold: float = 0.15) -> bool:
    """True when at least two scripts each hold more than ``threshold`` of the
    letters — the signal for code-switching or transliteration."""
    shares = script_shares(text)
    strong = [s for s, v in shares.items() if v >= threshold]
    return len(strong) >= 2
