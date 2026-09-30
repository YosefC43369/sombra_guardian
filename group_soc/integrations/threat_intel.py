"""
group_soc/integrations/threat_intel.py — optional IOC lookup adapter.

Gated by ``SOC_INTEL_ENRICHMENT_ENABLED`` (OFF by default, rule §17: no automatic
external calls, no member data leaving). When enabled, it looks up an indicator against
the local blueteam intel store (an already-ingested feed cache), NOT the live internet.
Returns a small dict or None. A missing intel module degrades to no-op.

This is a clean seam: a future online-enrichment implementation replaces ``lookup``
without changing callers.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("modbot.group_soc.integrations.intel")


class ThreatIntelAdapter:
    def __init__(self, config):
        self.config = config
        self._lookup_fn = None
        # Resolve a local lookup callable from blueteam.intel if present.
        try:
            from blueteam.intel.lookup import lookup as _lookup  # type: ignore
            self._lookup_fn = _lookup
        except Exception:
            logger.info("blueteam.intel lookup unavailable; SOC intel enrichment is a no-op")

    @property
    def enabled(self) -> bool:
        return bool(self.config.capability_enabled("intel_enrichment") and self._lookup_fn)

    def lookup(self, indicator: str, kind: str = "domain") -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        try:
            return self._lookup_fn(indicator, kind)  # local cache only
        except Exception:
            logger.debug("intel lookup failed for %s", kind, exc_info=True)
            return None
