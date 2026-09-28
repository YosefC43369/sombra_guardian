"""
blueteam/textkit.py — text normalization, confusable/homoglyph skeletons, and
near-duplicate hashing (SimHash) used across the Blue Team modules.

Reuse, don't duplicate (กติกาข้อ 2 ของโมดูล B)
------------------------------------------------
Thai/English message normalization is already solved in ``detection.py``
(``normalize_text``: NFKC, zero-width removal, whitespace, spaced-out-evasion
collapse). We delegate to it and only *add* the pieces the Blue Team modules
need on top:

  * :func:`collapse_thai_tone_marks` — collapse repeated Thai tone/vowel marks
    ("สาาาววว" -> "สาว") that scammers use to dodge lexicons;
  * :func:`skeleton` — a confusable/homoglyph + leetspeak *skeleton* so
    "𝗣𝗮𝘆𝗣𝗮𝗹", "pа𝗒pal" (Cyrillic a) and "p4yp4l" all fold onto "paypal" for
    brand-impersonation comparison (Unicode TR39 idea, compact built-in table
    extendable from the reference pack);
  * :func:`simhash` / :func:`hamming` — 64-bit SimHash over token shingles to
    cluster near-identical messages across senders (campaign detection);
  * :func:`damerau_levenshtein` and :func:`jaro_winkler` — bounded string
    distances for brand/username look-alike scoring.

Everything is pure stdlib and deterministic (unit-testable, no I/O).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Dict, Iterable, List, Optional

__all__ = [
    "normalize", "collapse_thai_tone_marks", "skeleton", "simhash", "hamming",
    "simhash_distance", "damerau_levenshtein", "jaro_winkler",
    "set_confusables", "tokens",
]

# --- delegate to the repo's normalizer, with a safe standalone fallback -------
try:
    from detection import normalize_text as _repo_normalize
except Exception:                                # pragma: no cover - detection always present
    _repo_normalize = None

_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿᠎]")
_WS_RE = re.compile(r"\s+")

# Thai combining tone marks (mai ek..mai chattawa) and above/below vowels that
# get spammed repeatedly. Collapsing 2+ identical combining marks to one is safe
# for real Thai (no valid word stacks the same tone mark twice).
_THAI_COMBINING = "ัิีึืฺุู็่้๊๋์ํ๎"
_THAI_COMBINING_DUP_RE = re.compile("([" + _THAI_COMBINING + "])\\1+")


def normalize(text: str) -> str:
    """Normalize a message for analysis (delegates to ``detection.normalize_text``).

    Falls back to an equivalent inline pipeline if detection.py is unavailable,
    so textkit stays importable in isolation for unit tests.
    """
    if not text:
        return ""
    if _repo_normalize is not None:
        try:
            return _repo_normalize(text)
        except Exception:
            pass
    t = unicodedata.normalize("NFKC", text)
    t = _ZERO_WIDTH_RE.sub("", t)
    return _WS_RE.sub(" ", t).strip()


def collapse_thai_tone_marks(text: str) -> str:
    """Collapse runs of the same Thai combining mark to a single one."""
    if not text:
        return ""
    return _THAI_COMBINING_DUP_RE.sub(r"\1", text)


# --- confusable / homoglyph skeleton -----------------------------------------
# Compact built-in confusable table: common Cyrillic/Greek/symbol look-alikes ->
# Latin, plus leetspeak. NFKC already folds fullwidth/most math-alphanumerics, so
# this focuses on the cross-script look-alikes NFKC does NOT fold. Extendable at
# runtime from reference_data/blueteam/confusables.json via set_confusables().
_BUILTIN_CONFUSABLES: Dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    # Greek -> Latin
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v",
    "Α": "a", "Ο": "o", "Β": "b", "Ε": "e", "Η": "h",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ρ": "p", "Τ": "t",
    "Χ": "x",
    # leetspeak / symbol substitutions
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
    "$": "s", "!": "i", "|": "l",
}
_confusables: Dict[str, str] = dict(_BUILTIN_CONFUSABLES)

_SKELETON_STRIP_RE = re.compile(r"[\s._\-]+")


def set_confusables(mapping: Optional[Dict[str, str]]) -> None:
    """Replace/extend the confusable table (called by the reference-pack loader).
    ``None`` resets to the built-in table."""
    global _confusables
    if mapping is None:
        _confusables = dict(_BUILTIN_CONFUSABLES)
    else:
        merged = dict(_BUILTIN_CONFUSABLES)
        merged.update({str(k): str(v) for k, v in mapping.items()})
        _confusables = merged


def skeleton(text: str) -> str:
    """Fold ``text`` to a confusable skeleton for look-alike comparison.

    Steps: NFKC (folds fullwidth/mathematical alphabets) -> strip diacritics ->
    lowercase -> map cross-script confusables + leetspeak -> drop separators.
    "𝗣𝗮𝘆𝗣𝗮𝗹" / "pаypаl" (Cyrillic) / "p4y-p4l" all fold to "paypal".
    """
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = _ZERO_WIDTH_RE.sub("", t)
    # strip Latin combining diacritics only (leave non-Latin scripts intact)
    nfkd = unicodedata.normalize("NFKD", t)
    t = "".join(c for c in nfkd if not (0x0300 <= ord(c) <= 0x036F))
    t = t.lower()
    t = "".join(_confusables.get(ch, ch) for ch in t)
    return _SKELETON_STRIP_RE.sub("", t)


# --- tokenisation + SimHash ---------------------------------------------------
_TOKEN_RE = re.compile(r"[0-9a-z฀-๿]+")


def tokens(text: str) -> List[str]:
    """Lowercase alphanumeric + Thai tokens from normalized text."""
    return _TOKEN_RE.findall(normalize(text).lower())


def _features(text: str) -> List[str]:
    """Feature set for SimHash: character n-grams over the normalized text with
    separators removed, PLUS whole word tokens.

    Character n-grams (not word shingles) are essential because Thai is written
    without spaces between words — word-level shingles would make two nearly
    identical Thai messages look completely different. Char 3-grams are
    script-agnostic and robust to small edits, spacing and reordering; adding the
    word tokens helps short English messages.
    """
    compact = "".join(tokens(text))            # normalized, lowercased, no spaces
    grams: List[str] = []
    n = 3
    if len(compact) >= n:
        grams = [compact[i:i + n] for i in range(len(compact) - n + 1)]
    elif compact:
        grams = [compact]
    grams.extend(tokens(text))
    return grams


def _hash64(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8"), digest_size=8).digest(),
                          "big")


def simhash(text: str, bits: int = 64) -> int:
    """64-bit SimHash over character n-grams (+ word tokens). Near-identical
    texts — even with small edits, spacing changes or reordering, in Thai or
    English — produce hashes a small Hamming distance apart."""
    features = _features(text)
    if not features:
        return 0
    vector = [0] * bits
    for feat in features:
        h = _hash64(feat)
        for i in range(bits):
            vector[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if vector[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def simhash_distance(text_a: str, text_b: str) -> int:
    return hamming(simhash(text_a), simhash(text_b))


# --- string distances ---------------------------------------------------------
def damerau_levenshtein(a: str, b: str, max_distance: Optional[int] = None) -> int:
    """Damerau-Levenshtein distance with adjacent transpositions (full matrix).

    Inputs here are short (brand names, usernames), so the exact O(n*m) matrix is
    both correct and cheap. ``max_distance`` short-circuits once an entire row
    exceeds it, returning ``max_distance + 1`` — enough for a "close enough?"
    test without finishing the computation.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        row_min = d[i][0]
        ai = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            val = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if (i > 1 and j > 1 and ai == b[j - 2] and a[i - 2] == b[j - 1]):
                val = min(val, d[i - 2][j - 2] + 1)
            d[i][j] = val
            if val < row_min:
                row_min = val
        if max_distance is not None and row_min > max_distance:
            return max_distance + 1
    return d[la][lb]


def jaro_winkler(a: str, b: str, prefix_weight: float = 0.1) -> float:
    """Jaro-Winkler similarity in [0, 1] (1 = identical). Good at catching
    look-alike display names/usernames that share a prefix."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    match_dist = max(la, lb) // 2 - 1
    if match_dist < 0:
        match_dist = 0
    a_matches = [False] * la
    b_matches = [False] * lb
    matches = 0
    for i in range(la):
        lo = max(0, i - match_dist)
        hi = min(i + match_dist + 1, lb)
        for j in range(lo, hi):
            if b_matches[j] or a[i] != b[j]:
                continue
            a_matches[i] = b_matches[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    t = 0
    k = 0
    for i in range(la):
        if not a_matches[i]:
            continue
        while not b_matches[k]:
            k += 1
        if a[i] != b[k]:
            t += 1
        k += 1
    t /= 2
    jaro = (matches / la + matches / lb + (matches - t) / matches) / 3
    prefix = 0
    for i in range(min(4, la, lb)):
        if a[i] == b[i]:
            prefix += 1
        else:
            break
    return jaro + prefix * prefix_weight * (1 - jaro)
