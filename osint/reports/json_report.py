"""osint.reports.json_report — serialize an Intelligence object to JSON.

Stable, sorted keys so two runs over the same data diff cleanly and a hash of
the report is reproducible (the same discipline the integrity ledger uses)."""

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:                      # avoid a runtime import cycle
    from ..orchestrator import Intelligence


def render(intel: "Intelligence", *, indent: int = 2) -> str:
    return json.dumps(intel.to_dict(), ensure_ascii=False, sort_keys=True,
                      indent=indent)
