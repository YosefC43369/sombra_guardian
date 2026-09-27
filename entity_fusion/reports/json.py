"""entity_fusion.reports.json — serialize a FusionResult (or Identity list) to
stable, sorted JSON so two runs over the same data diff cleanly and a report
hash is reproducible (the discipline the integrity ledger relies on)."""

from __future__ import annotations

import json as _json
from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:                       # avoid runtime import cycle
    from ..orchestrator import FusionResult
    from ..identity import Identity


def render(result: "FusionResult", *, indent: int = 2) -> str:
    return _json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True,
                       indent=indent)


def render_identities(identities: "List[Identity]", *, indent: int = 2) -> str:
    payload: Dict[str, Any] = {"identities": [i.to_dict() for i in identities]}
    return _json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=indent)
