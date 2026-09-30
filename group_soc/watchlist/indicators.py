"""
group_soc/watchlist/indicators.py — normalize indicator kinds/values.

Keeps watchlist values in the same normalized form the normalizer produces, so a
watch actually matches ingested events: domains lowercased+defanged, urls defanged,
kinds validated. A raw user id passed as a 'user' kind is left to the manager to hash.
"""

from __future__ import annotations

from typing import Tuple

from ..constants import EntityKind, VALID_ENTITY_KINDS
from ..exceptions import SocValidationError
from ..util import defang


def normalize_indicator(kind: str, value: str) -> Tuple[str, str]:
    kind = str(kind or "").lower().strip()
    if kind not in VALID_ENTITY_KINDS:
        raise SocValidationError("invalid watchlist kind", code="SOC_VALIDATION_ERROR",
                                 kind=kind)
    value = str(value or "").strip()
    if not value:
        raise SocValidationError("empty watchlist value", code="SOC_VALIDATION_ERROR")
    if kind == EntityKind.DOMAIN.value:
        value = defang(value.lower())
    elif kind == EntityKind.URL.value:
        value = defang(value)
    else:
        value = value.lower()
    return kind, value
