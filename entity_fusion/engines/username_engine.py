"""
entity_fusion.engines.username_engine — canonicalize handles and generate the
variant set a single person is likely to reuse across platforms.

SOCMINT modules find handles; correlation needs to know that ``john.doe``,
``johndoe``, ``john_doe90``, ``j0hn.doe`` and ``JohnDoe`` are one person's naming
habit. This engine:

  * canonicalizes to a stable key (via ``normalization.canonical_username``),
  * records the homoglyph skeleton and handle-core (numeric suffix stripped),
  * generates plausible variants (separator styles, case, leet, numeric
    suffixes, an ASCII transliteration) for cross-platform search,
  * flags a handle that is a homoglyph spoof of a known brand/handle.

Generation is bounded (``max_variants``) so a pathological handle cannot explode
the candidate set. Pure stdlib.
"""

from __future__ import annotations

import itertools
import unicodedata
from typing import List, Set

from ..entity import Entity, EntityType, Evidence
from .. import normalization as norm
from .base import CorrelationEngine, EngineResult


def transliterate_ascii(text: str) -> str:
    """Best-effort ASCII fold via NFKD + combining-mark removal (``café`` →
    ``cafe``). Not a full transliteration (no Cyrillic→Latin phonetics) — just
    the accent-stripping that recovers the most common ASCII spelling."""
    decomposed = unicodedata.normalize("NFKD", text)
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c)
                         and ord(c) < 128)
    return ascii_only


def generate_variants(handle: str, *, max_variants: int = 40) -> List[str]:
    """Produce a de-duplicated, bounded list of handle variants for search."""
    canon = norm.canonical_username(handle)
    if not canon:
        return []
    variants: Set[str] = {canon}
    core = norm.username_core(handle)
    variants.add(core)

    # separator styles applied to the core token pair, if the handle splits
    tokens = [t for t in norm.normalize_text(handle, casefold=True)
              .replace(".", " ").replace("_", " ").replace("-", " ").split() if t]
    if len(tokens) >= 2:
        joined = tokens[0], tokens[-1]
        for sep in ("", ".", "_", "-"):
            variants.add(sep.join(joined))
        variants.add(f"{joined[0][0]}{joined[1]}")     # jdoe
        variants.add(f"{joined[0]}{joined[1][0]}")     # johnd

    # leet fold and its inverse-ish common substitutions
    variants.add(norm.leet_defang(handle))

    # transliteration
    trans = norm.canonical_username(transliterate_ascii(handle))
    if trans:
        variants.add(trans)

    # numeric suffixes on the core (common reuse pattern)
    if core and core.isascii():
        for suffix in ("", "1", "01", "123", "2024", "007"):
            variants.add(core + suffix)

    variants.discard("")
    ordered = sorted(variants, key=lambda v: (v != canon, len(v), v))
    return ordered[:max_variants]


class UsernameEngine(CorrelationEngine):
    name = "username_engine"
    handles = (EntityType.USERNAME,)

    def __init__(self, *, known_handles: Set[str] = None, max_variants: int = 40):
        # Optional watchlist of handles/brands to flag homoglyph spoofing against.
        # Stored as originals; skeletons are computed at compare time so a spoof
        # (which shares the skeleton but differs in codepoints) is distinguishable
        # from the genuine handle.
        self.known_handles = set(known_handles or set())
        self.max_variants = max_variants

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        canon = norm.canonical_username(entity.value)
        if not canon:
            return result
        result.derived["canonical_username"] = canon
        result.derived["username_core"] = norm.username_core(entity.value)
        result.derived["username_skeleton"] = norm.skeleton(entity.value)
        result.derived["username_variants"] = generate_variants(
            entity.value, max_variants=self.max_variants)

        # register the core as an alias so blocking/similarity can use it
        entity.add_alias(canon)

        skel = norm.skeleton(entity.value)
        raw = entity.value.strip()
        has_non_ascii = any(ord(c) > 127 for c in raw)
        for known in self.known_handles:
            # A spoof shares the skeleton but is NOT the genuine handle: either it
            # carries non-ASCII look-alike codepoints, or it differs from the
            # watchlisted spelling while collapsing to the same skeleton.
            if skel and norm.skeleton(known) == skel and raw.lower() != known.strip().lower():
                if has_non_ascii or raw != known:
                    result.evidence.append(Evidence(
                        kind="homoglyph_spoof_suspected", value=entity.value,
                        weight=-0.3,
                        note=f"handle resembles watchlisted {known!r} "
                             f"(shared skeleton {skel!r})"))
                    break
        return result
