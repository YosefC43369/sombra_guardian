"""
behavioral_intelligence.linguistic.transliteration — transliteration analysis
(spec §11).

Romanises non-Latin tokens using character-level tables (Thai, Cyrillic, Arabic,
Japanese kana) and compares them against candidate Latin aliases with a
normalised edit-distance similarity. This surfaces relationships like the Latin
spelling of a Thai/Russian handle — SUPPORTING EVIDENCE ONLY. A transliteration
match is never treated as identity proof (the caller attaches that limitation).

Han (Chinese) romanisation needs a large pinyin table and an external dependency;
it is intentionally out of scope for this stdlib core, and such tokens are
reported as ``method='unsupported_script'`` rather than silently mishandled.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from ..models.language import TransliterationMatch
from . import script_detector

# --- character romanisation tables (pragmatic, not scholarly standards) ----- #

_CYRILLIC = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}

_THAI = {
    "ก": "k", "ข": "kh", "ค": "kh", "ง": "ng", "จ": "ch", "ฉ": "ch", "ช": "ch",
    "ซ": "s", "ญ": "y", "ด": "d", "ต": "t", "ถ": "th", "ท": "th", "ธ": "th",
    "น": "n", "บ": "b", "ป": "p", "ผ": "ph", "ฝ": "f", "พ": "ph", "ฟ": "f",
    "ภ": "ph", "ม": "m", "ย": "y", "ร": "r", "ล": "l", "ว": "w", "ศ": "s",
    "ษ": "s", "ส": "s", "ห": "h", "อ": "o", "ฮ": "h",
    "ะ": "a", "า": "a", "ิ": "i", "ี": "i", "ึ": "ue", "ื": "ue", "ุ": "u",
    "ู": "u", "เ": "e", "แ": "ae", "โ": "o", "ใ": "ai", "ไ": "ai", "ำ": "am",
    "่": "", "้": "", "๊": "", "๋": "", "็": "", "์": "",
}

_ARABIC = {
    "ا": "a", "ب": "b", "ت": "t", "ث": "th", "ج": "j", "ح": "h", "خ": "kh",
    "د": "d", "ذ": "dh", "ر": "r", "ز": "z", "س": "s", "ش": "sh", "ص": "s",
    "ض": "d", "ط": "t", "ظ": "z", "ع": "a", "غ": "gh", "ف": "f", "ق": "q",
    "ك": "k", "ل": "l", "م": "m", "ن": "n", "ه": "h", "و": "w", "ي": "y",
    "ى": "a", "ة": "h", "ء": "",
}

_HIRAGANA = {
    "あ": "a", "い": "i", "う": "u", "え": "e", "お": "o", "か": "ka", "き": "ki",
    "く": "ku", "け": "ke", "こ": "ko", "さ": "sa", "し": "shi", "す": "su",
    "せ": "se", "そ": "so", "た": "ta", "ち": "chi", "つ": "tsu", "て": "te",
    "と": "to", "な": "na", "に": "ni", "ぬ": "nu", "ね": "ne", "の": "no",
    "は": "ha", "ひ": "hi", "ふ": "fu", "へ": "he", "ほ": "ho", "ま": "ma",
    "み": "mi", "む": "mu", "め": "me", "も": "mo", "や": "ya", "ゆ": "yu",
    "よ": "yo", "ら": "ra", "り": "ri", "る": "ru", "れ": "re", "ろ": "ro",
    "わ": "wa", "を": "wo", "ん": "n",
}


def _table_for(script: str) -> Optional[Dict[str, str]]:
    return {"Cyrillic": _CYRILLIC, "Thai": _THAI, "Arabic": _ARABIC,
            "Hiragana": _HIRAGANA}.get(script)


def romanize(text: str) -> str:
    """Best-effort character-level romanisation of the dominant non-Latin script.
    Latin text is returned casefolded; unsupported scripts return ''."""
    if not text:
        return ""
    script = script_detector.dominant_script(text)
    if script == "Latin":
        return text.casefold()
    table = _table_for(script)
    if table is None:
        return ""
    out = []
    for ch in text:
        out.append(table.get(ch, "" if not ch.isalnum() else ch.casefold()))
    return "".join(out)


def _similarity(a: str, b: str) -> float:
    """1 - normalised Levenshtein distance, in [0,1]."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    dist = prev[lb]
    return 1.0 - dist / max(la, lb)


def compare_alias(non_latin_token: str, latin_candidate: str) -> TransliterationMatch:
    """Compare a non-Latin token's romanisation to a Latin candidate alias."""
    script = script_detector.dominant_script(non_latin_token)
    table = _table_for(script)
    if script in ("Han",) or (table is None and script != "Latin"):
        return TransliterationMatch(source_token=non_latin_token,
                                    latin_form="", script=script,
                                    method="unsupported_script", similarity=0.0)
    roman = romanize(non_latin_token)
    sim = _similarity(roman, latin_candidate.casefold())
    return TransliterationMatch(source_token=non_latin_token, latin_form=roman,
                                script=script, method="romanization_table",
                                similarity=sim)


def match_aliases(non_latin_tokens: Sequence[str], latin_candidates: Sequence[str],
                  *, min_similarity: float = 0.6) -> List[TransliterationMatch]:
    """Cross-compare every non-Latin token against every Latin candidate; keep
    matches above ``min_similarity``, best first."""
    out: List[TransliterationMatch] = []
    for tok in non_latin_tokens:
        for cand in latin_candidates:
            m = compare_alias(tok, cand)
            if m.similarity >= min_similarity:
                out.append(m)
    out.sort(key=lambda m: m.similarity, reverse=True)
    return out
