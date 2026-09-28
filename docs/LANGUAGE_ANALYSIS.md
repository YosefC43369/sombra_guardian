# Language Analysis

Module: `behavioral_intelligence/linguistic/`. Reports observable **language use**
in public text. It never infers nationality, ethnicity or first language — that
limitation is attached wherever language results feed an assertion.

## Script detection (`script_detector.py`)

Classifies each letter by Unicode codepoint range into a writing system —
Latin, Greek, Cyrillic, Hebrew, Arabic, Devanagari, Thai, Hangul, Hiragana,
Katakana, Han — and returns per-script shares. `is_mixed_script` flags
code-switching / transliteration when ≥2 scripts each hold a meaningful share.

## Language detection (`language_detector.py`)

Two signals, no external model:

1. **Script** — Thai / kana / Hangul / Arabic / Hebrew / Cyrillic / Devanagari
   map near-deterministically. Han **with** kana → Japanese; Han **without** →
   Chinese.
2. **Stopwords** — Latin-script languages (en/es/fr/de/pt/id/ms/vi) are separated
   by scoring against small high-frequency function-word sets.

Returns a calibrated confidence, the script breakdown, and a `mixed` flag. Empty
text → `und` (undetermined), confidence 0.

Supported (spec §9): English, Thai, Japanese, Chinese, Korean, Arabic, Hebrew,
Russian, Spanish, French, German, Portuguese, Indonesian, Vietnamese, Malay.

## Language switching (`language_switching.py`, §10)

- `distribution` — language mix over a window.
- `timeline` — per-month/week language distribution.
- `switches` / `switching_frequency` — observed changes of dominant language.
- `platform_language_matrix` — `{platform: {language: share}}`.

## Transliteration (`transliteration.py`, §11)

Character-level romanisation tables (Thai, Cyrillic, Arabic, Japanese kana) plus a
normalised edit-distance similarity, to compare a non-Latin token against a Latin
alias. **Supporting evidence only** — never identity proof. Han (Chinese) needs a
pinyin table and is reported as `unsupported_script` rather than mishandled.

## Keywords / phrases / hashtags / terminology

- `keyword_engine` — TF-IDF salience, burst score, first/last-seen,
  co-occurrence. Thai/CJK runs are segmented into character bigrams so they are
  not dropped.
- `phrase_engine` — recurring 2–5-grams (only phrases that repeat are surfaced;
  raw surrounding text is not exposed).
- `hashtag_engine` — frequency, rising/declining trend, co-occurrence.
- `terminology` — technical identifiers (CVE, CWE, acronyms, versions, hashes,
  commands, handles) for footprint mapping.
