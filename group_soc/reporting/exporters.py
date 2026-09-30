"""group_soc/reporting/exporters.py — serialize a report dict for external tooling."""

from __future__ import annotations

import json
from typing import Any, Dict


def export_json(report: Dict[str, Any], *, indent: int = 2) -> str:
    return json.dumps(report, ensure_ascii=False, indent=indent, sort_keys=True, default=str)
