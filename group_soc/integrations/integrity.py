"""
group_soc/integrations/integrity.py — anchor SOC incidents into the tamper-evident ledger.

Reuses the existing integrity_ledger (same helper sg_platform wires for workflow events)
so a SOC incident's creation/resolution is recorded in a verifiable, append-only log.
Only a compact, non-PII fingerprint is anchored — never the full record. Degrades to a
no-op if integrity_ledger is unavailable.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("modbot.group_soc.integrations.integrity")


class IntegrityAnchor:
    def __init__(self):
        self._il = None
        try:
            import integrity_ledger as il
            self._il = il
        except Exception:
            logger.info("integrity_ledger unavailable; SOC anchoring disabled")

    @property
    def available(self) -> bool:
        return self._il is not None

    def anchor(self, chat_id: int, event_type: str, fingerprint: Dict[str, Any]) -> Optional[int]:
        if self._il is None or chat_id is None:
            return None
        try:
            result = self._il.record_event(int(chat_id), event_type, fingerprint,
                                           actor="group_soc")
            if getattr(result, "ok", False):
                entry = result.data.get("entry") if hasattr(result, "data") else None
                return entry.get("seq") if entry else None
        except Exception:
            logger.exception("SOC integrity anchor failed for %s", event_type)
        return None
