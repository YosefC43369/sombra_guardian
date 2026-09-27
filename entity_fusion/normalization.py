"""
entity_fusion.normalization — turn messy, multilingual, adversarially-spelled
identifiers into stable canonical forms so that two records for the same thing
compare equal.

WHY THIS MATTERS. Correlation is only as good as its keys. ``JohnDoe``,
``john.doe``, ``ｊｏｈｎ_ｄｏｅ`` (fullwidth), ``john‑doe`` (non-ASCII hyphen) and
``jοhn.doe`` (Greek omicron homoglyph) are all the *same handle* to a human and
five different strings to ``==``. This module collapses those differences with a
layered pipeline:

  1. Unicode NFKC (fold compatibility forms: fullwidth → ASCII, ligatures, …)
  2. Homoglyph / confusable skeleton (map look-alike codepoints to a base set)
  3. Script-aware cleanup (combining marks for Arabic/Hebrew/Thai/CJK, ZWJ/ZWNJ)
  4. Emoji + control-character removal
  5. Whitespace normalization

On top of the general pipeline sit type-specific canonicalizers that encode the
real-world equivalence rules for each identifier kind (email plus-addressing and
Gmail dot-folding, username separator folding and leet expansion, phone → E.164
digits, URL/domain punycode).

Standard library only: ``unicodedata`` + ``re``. A full Unicode confusables
table is enormous; the curated ``_CONFUSABLES`` map here covers the codepoints
that actually appear in handle/domain spoofing (Cyrillic/Greek Latin look-alikes,
fullwidth, common math-alphanumeric styling) — extend it as new abuse is seen.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Optional


# --------------------------------------------------------------------------- #
# Confusable / homoglyph folding                                               #
# --------------------------------------------------------------------------- #
# Map look-alike codepoints to a canonical ASCII base. This is the heart of
# homoglyph *detection*: fold to skeleton, then two strings that "look the same"
# share a skeleton even though their codepoints differ.

_CONFUSABLES: Dict[str, str] = {
    # Cyrillic → Latin look-alikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "ѕ": "s", "А": "a", "Е": "e", "О": "o", "Р": "p",
    "С": "c", "Т": "t", "Х": "x", "М": "m", "Н": "h",
    "К": "k", "В": "b",
    # Greek → Latin look-alikes
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h",
    "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    # Common punctuation look-alikes
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-",
    "―": "-", "−": "-", "－": "-",
    "․": ".", "．": ".", "。": ".",
    "⁄": "/", "／": "/",
    "ı": "i",   # dotless i
    "⁄": "/",
}


def _fold_confusables(text: str) -> str:
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text)


# Emoji and symbol blocks we strip from handles/bios before comparison. We remove
# by Unicode category (So/Cs) plus the main emoji ranges rather than a hardcoded
# list, so new emoji are covered without a table update.
_EMOJI_RANGES = [
    (0x1F300, 0x1FAFF),   # symbols & pictographs, supplemental, extended-A
    (0x1F000, 0x1F02F),   # mahjong / dominoes / cards
    (0x2600, 0x27BF),     # misc symbols + dingbats
    (0xFE00, 0xFE0F),     # variation selectors
    (0x1F1E6, 0x1F1FF),   # regional indicators (flags)
]

# Zero-width and directional formatting characters used to smuggle
# indistinguishable strings past naive comparison.
_ZERO_WIDTH = {
    "​", "‌", "‍", "⁠", "﻿",
    "‎", "‏", "‪", "‫", "‬", "‭", "‮",
}


def _is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _EMOJI_RANGES)


def strip_emoji(text: str) -> str:
    return "".join(ch for ch in text if not _is_emoji(ch))


def strip_zero_width(text: str) -> str:
    return "".join(ch for ch in text if ch not in _ZERO_WIDTH)


def strip_controls(text: str) -> str:
    """Drop control characters (category Cc/Cf) except normal whitespace."""
    out = []
    for ch in text:
        if ch in ("\t", "\n", "\r", " "):
            out.append(ch)
            continue
        if unicodedata.category(ch) in ("Cc", "Cf"):
            continue
        out.append(ch)
    return "".join(out)


def collapse_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# --------------------------------------------------------------------------- #
# General pipeline                                                             #
# --------------------------------------------------------------------------- #

def normalize_text(raw: Optional[str], *, fold_confusables: bool = False,
                   drop_emoji: bool = True, casefold: bool = True) -> str:
    """The general normalization pipeline for free text (display names, bios).

    NFKC first (compatibility fold), then zero-width/control/emoji stripping,
    optional confusable folding, optional casefold, whitespace collapse. Returns
    ``""`` for falsy input — never None — so callers can compare directly."""
    if not raw:
        return ""
    text = unicodedata.normalize("NFKC", str(raw))
    text = strip_zero_width(text)
    text = strip_controls(text)
    if drop_emoji:
        text = strip_emoji(text)
    if fold_confusables:
        text = _fold_confusables(text)
    if casefold:
        text = text.casefold()
    return collapse_whitespace(text)


def skeleton(raw: Optional[str]) -> str:
    """The homoglyph *skeleton* of a string: NFKC + confusable-fold +
    lowercase + remove all non-alphanumerics. Two strings that a human would
    read as identical share a skeleton — the primary homoglyph-attack detector.

        skeleton("paypal")  == skeleton("pаypаl")   # Cyrillic 'а'
        skeleton("john.doe") == skeleton("john_doe")
    """
    if not raw:
        return ""
    text = unicodedata.normalize("NFKC", str(raw))
    text = strip_zero_width(strip_controls(text))
    text = _fold_confusables(text).casefold()
    text = "".join(ch for ch in unicodedata.normalize("NFKD", text)
                   if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", text)


def looks_confusable(a: str, b: str) -> bool:
    """True if two distinct strings collapse to the same skeleton — i.e. one is
    a plausible homoglyph spoof of the other."""
    return a != b and bool(skeleton(a)) and skeleton(a) == skeleton(b)


# --------------------------------------------------------------------------- #
# Script-specific helpers                                                      #
# --------------------------------------------------------------------------- #

def strip_combining(text: str) -> str:
    """Remove combining marks via NFKD decomposition. Applies broadly — Latin
    accents, Arabic/Hebrew vowel points (harakat/niqqud), Thai tone marks — so
    that diacritic-only differences do not defeat correlation."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def normalize_arabic(raw: Optional[str]) -> str:
    """Canonical Arabic: strip tashkeel/tatweel, unify alef/ya/ta-marbuta forms.
    These are the standard equivalence rules for Arabic text search."""
    if not raw:
        return ""
    text = unicodedata.normalize("NFKC", str(raw))
    text = re.sub("[ؗ-ًؚ-ْـ]", "", text)  # harakat + tatweel
    text = re.sub("[آأإٱ]", "ا", text)     # alef variants → ا
    text = text.replace("ى", "ي")                          # alef maqsura → ya
    text = text.replace("ة", "ه")                          # ta marbuta → ha
    return collapse_whitespace(text)


def normalize_hebrew(raw: Optional[str]) -> str:
    """Canonical Hebrew: strip niqqud (vowel points) and cantillation marks."""
    if not raw:
        return ""
    text = unicodedata.normalize("NFKC", str(raw))
    text = re.sub("[֑-ׇֽֿׁׂׅׄ]", "", text)
    return collapse_whitespace(text)


def normalize_thai(raw: Optional[str]) -> str:
    """Canonical Thai: NFC + strip tone marks so toneless spellings match."""
    if not raw:
        return ""
    text = unicodedata.normalize("NFC", str(raw))
    text = re.sub("[็-๎]", "", text)   # tone marks + thanthakhat
    return collapse_whitespace(text)


def normalize_cjk(raw: Optional[str]) -> str:
    """Canonical CJK (Chinese/Japanese/Korean): NFKC folds fullwidth/halfwidth
    and compatibility ideographs; whitespace collapsed. Simplified/traditional
    unification is intentionally NOT attempted here (it is lossy and needs a
    dictionary) — only mechanical Unicode equivalence."""
    if not raw:
        return ""
    return collapse_whitespace(unicodedata.normalize("NFKC", str(raw)))


# --------------------------------------------------------------------------- #
# Type-specific canonicalizers                                                 #
# --------------------------------------------------------------------------- #

# Conservative leetspeak map for username variant expansion (not applied to the
# canonical form — used by the username engine to *generate* candidates).
_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
         "@": "a", "$": "s", "!": "i"}


def canonical_username(raw: Optional[str]) -> str:
    """Canonical handle: NFKC, confusable-fold, casefold, drop emoji/zero-width,
    then remove separators (``.`` ``_`` ``-`` space). ``John.Doe``,
    ``john_doe`` and ``john-doe`` all canonicalize to ``johndoe``. A leading ``@``
    is dropped."""
    if not raw:
        return ""
    text = normalize_text(raw, fold_confusables=True, drop_emoji=True, casefold=True)
    text = text.lstrip("@").strip()
    text = strip_combining(text)
    return re.sub(r"[.\-_\s]+", "", text)


def username_core(raw: Optional[str]) -> str:
    """The handle with any trailing numeric suffix removed, on the canonical
    form. ``john_doe_1990`` and ``johndoe`` share the core ``johndoe`` — used as
    a *weaker* correlation key than the full canonical handle."""
    canon = canonical_username(raw)
    return re.sub(r"\d+$", "", canon) or canon


def leet_defang(raw: Optional[str]) -> str:
    """Fold common leet substitutions to letters. ``h4ck3r`` → ``hacker``. Used
    to generate correlation candidates, not as the stored canonical form."""
    canon = canonical_username(raw)
    return "".join(_LEET.get(ch, ch) for ch in canon)


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Providers that ignore dots in the local-part and/or treat everything after a
# '+' as a tag. Folding these lets alias addresses correlate to one mailbox.
_DOT_FOLDING_DOMAINS = {"gmail.com", "googlemail.com"}


def canonical_email(raw: Optional[str]) -> str:
    """Canonical email address.

    Lower-cases, IDNA-encodes the domain, strips ``+tag`` sub-addressing, and for
    dot-folding providers (Gmail) removes dots from the local-part. Returns ``""``
    if the input is not a structurally valid address — never a partial string."""
    if not raw:
        return ""
    text = normalize_text(raw, drop_emoji=True, casefold=True)
    text = text.replace(" ", "")
    if not _EMAIL_RE.match(text):
        return ""
    local, _, domain = text.rpartition("@")
    domain = domain.rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except Exception:
        pass
    local = local.split("+", 1)[0]
    if domain in _DOT_FOLDING_DOMAINS:
        local = local.replace(".", "")
    if not local:
        return ""
    return f"{local}@{domain}"


def email_domain(raw: Optional[str]) -> str:
    canon = canonical_email(raw)
    return canon.rpartition("@")[2] if canon else ""


_URL_TRACKING_PARAMS = re.compile(
    r"^(utm_|fbclid$|gclid$|mc_|ref$|ref_src$|igshid$|si$)", re.IGNORECASE)


def canonical_url(raw: Optional[str]) -> str:
    """Canonical URL for correlation: lower-case scheme+host, IDNA host, drop
    default ports, drop a trailing slash, strip common tracking query params,
    and drop the fragment. Uses ``urllib.parse`` (stdlib)."""
    if not raw:
        return ""
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    text = normalize_text(raw, drop_emoji=True, casefold=False).strip()
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except Exception:
        pass
    port = parts.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = re.sub(r"/+$", "", parts.path) or "/"
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not _URL_TRACKING_PARAMS.match(k)]
    query = urlencode(sorted(kept))
    return urlunsplit((scheme, host, path if path != "/" else "", query, ""))


def canonical_domain(raw: Optional[str]) -> str:
    """A thin re-export of the ``osint`` domain normalizer if available, else a
    local IDNA lower-case fold. Kept here so ``entity_fusion`` has no hard import
    on ``osint`` (degraded standalone use), but reuses it when present."""
    if not raw:
        return ""
    try:  # prefer the battle-tested validator from the OSINT framework
        from osint.utils.validators import normalize_domain
        norm = normalize_domain(raw)
        if norm:
            return norm
    except Exception:
        pass
    text = normalize_text(raw, casefold=True).strip().strip(".")
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    text = text.split("/", 1)[0].split(":", 1)[0]
    if text.startswith("*."):
        text = text[2:]
    try:
        text = text.encode("idna").decode("ascii")
    except Exception:
        pass
    return text


# Country calling codes we recognize for a lightweight region hint. Not
# exhaustive — the phone engine layers a real region table on top. The point of
# canonicalization here is a stable digit key, not perfect region inference.
_DEFAULT_REGION_HINTS = {
    "1": "NANP", "44": "GB", "66": "TH", "49": "DE", "33": "FR",
    "34": "ES", "39": "IT", "31": "NL", "972": "IL", "971": "AE",
    "966": "SA", "20": "EG", "81": "JP", "86": "CN", "82": "KR",
    "91": "IN", "61": "AU", "7": "RU",
}


def canonical_phone(raw: Optional[str], *, default_cc: str = "") -> str:
    """Canonical phone number in E.164-ish form (``+`` then digits only).

    Strips spaces, hyphens, parentheses and dots; converts a ``00`` prefix to
    ``+``; and, if the number has no country code but a ``default_cc`` is given,
    prepends it. Returns ``""`` if fewer than 7 or more than 15 digits remain
    (E.164 bounds), so junk never becomes a correlation key."""
    if not raw:
        return ""
    text = normalize_text(str(raw), drop_emoji=True, casefold=False)
    text = text.strip()
    has_plus = text.lstrip().startswith("+")
    digits = re.sub(r"\D", "", text)
    if digits.startswith("00"):
        digits = digits[2:]
        has_plus = True
    if not has_plus and default_cc:
        cc = re.sub(r"\D", "", default_cc)
        # avoid double-prefixing a trunk '0'
        digits = cc + digits.lstrip("0")
    if not (7 <= len(digits) <= 15):
        return ""
    return "+" + digits


def phone_region_hint(e164: Optional[str]) -> str:
    """Best-effort region label from a canonical (+CC…) phone number."""
    if not e164 or not e164.startswith("+"):
        return ""
    digits = e164[1:]
    for length in (3, 2, 1):
        if len(digits) > length and digits[:length] in _DEFAULT_REGION_HINTS:
            return _DEFAULT_REGION_HINTS[digits[:length]]
    return ""


# --------------------------------------------------------------------------- #
# Dispatch                                                                     #
# --------------------------------------------------------------------------- #

def normalize_value(entity_type: str, value: str, *, default_cc: str = "") -> str:
    """Route a value to the right canonicalizer by entity type. Anything without
    a specific rule falls back to the general text pipeline. Import-cycle-free:
    accepts the type as a plain string."""
    t = str(entity_type).strip().lower()
    if t == "email":
        return canonical_email(value)
    if t == "username":
        return canonical_username(value)
    if t == "phone":
        return canonical_phone(value, default_cc=default_cc)
    if t in ("domain", "subdomain"):
        return canonical_domain(value)
    if t in ("website", "url"):
        return canonical_url(value)
    return normalize_text(value, casefold=True)
