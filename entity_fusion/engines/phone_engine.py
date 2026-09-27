"""
entity_fusion.engines.phone_engine — normalize public phone numbers to E.164 and
infer a coarse region/timezone hint.

Numbers appear on public contact pages, WHOIS records and profiles in a dozen
formats. This engine canonicalizes them to a single ``+CC…`` digit key so two
records for the same number correlate, and attaches a best-effort region label
and a representative timezone. It does no lookups — no carrier query, no
reverse-number service — it is a pure formatting/normalisation step over a
value already in hand.
"""

from __future__ import annotations

from typing import List

from ..entity import Entity, EntityType, Evidence
from .. import normalization as norm
from .base import CorrelationEngine, EngineResult


# Coarse region → representative timezone, for the timezone-similarity signal.
_REGION_TZ = {
    "NANP": "America/New_York", "GB": "Europe/London", "TH": "Asia/Bangkok",
    "DE": "Europe/Berlin", "FR": "Europe/Paris", "ES": "Europe/Madrid",
    "IT": "Europe/Rome", "NL": "Europe/Amsterdam", "IL": "Asia/Jerusalem",
    "AE": "Asia/Dubai", "SA": "Asia/Riyadh", "EG": "Africa/Cairo",
    "JP": "Asia/Tokyo", "CN": "Asia/Shanghai", "KR": "Asia/Seoul",
    "IN": "Asia/Kolkata", "AU": "Australia/Sydney", "RU": "Europe/Moscow",
}


class PhoneEngine(CorrelationEngine):
    name = "phone_engine"
    handles = (EntityType.PHONE,)

    def __init__(self, *, default_cc: str = ""):
        self.default_cc = default_cc

    def analyze(self, entity: Entity) -> EngineResult:
        result = EngineResult()
        e164 = norm.canonical_phone(entity.value, default_cc=self.default_cc)
        if not e164:
            result.evidence.append(Evidence(
                kind="phone_unparseable", value=entity.value, weight=-0.1,
                note="not a valid E.164-range number"))
            return result
        result.derived["e164"] = e164
        entity.normalized = e164
        region = norm.phone_region_hint(e164)
        if region:
            result.derived["phone_region"] = region
            tz = _REGION_TZ.get(region)
            if tz:
                result.derived.setdefault("timezone", tz)
        result.derived["phone_variants"] = self._format_variants(e164)
        return result

    @staticmethod
    def _format_variants(e164: str) -> List[str]:
        """Common human formattings of the canonical number, for text search."""
        if not e164.startswith("+"):
            return [e164]
        digits = e164[1:]
        out = {e164, digits, "00" + digits}
        if len(digits) >= 7:
            # group last 7 as ...-xxx-xxxx
            out.add(f"{e164[:-7]} {digits[-7:-4]} {digits[-4:]}")
        return sorted(out)
