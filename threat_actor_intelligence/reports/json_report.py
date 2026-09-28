"""
threat_actor_intelligence.reports.json_report — dossier → JSON.

A thin, deterministic serializer: the dossier dict is already the machine-readable
form, so this renders it with sorted keys for stable diffs and safe defaults for
any non-serializable value. Used by the Telegram ``/*_report`` exports and the
reporting-engine integration.
"""

from __future__ import annotations

import json
from typing import Any, Dict


def render(dossier: Dict[str, Any], *, indent: int = 2) -> str:
    return json.dumps(dossier, ensure_ascii=False, sort_keys=True, indent=indent,
                      default=str)


__all__ = ["render"]
