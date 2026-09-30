"""
purple_range/plans/loader.py — load curated plan fixtures from library/.

Reads every ``*.json`` in ``purple_range/plans/library/`` and validates it into a Plan.
A bad fixture is logged and skipped — one broken file never blocks the others (same
failure-isolation posture as the plugin loader). Standard library only (json).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Dict, List

from ..models import Plan
from .schema import validate_plan_dict

logger = logging.getLogger("modbot.purple_range.plans")

_LIBRARY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "library")


def load_library(directory: str = None) -> List[Plan]:
    directory = directory or _LIBRARY_DIR
    plans: List[Plan] = []
    if not os.path.isdir(directory):
        return plans
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json") or name.startswith("_"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            data.setdefault("source", "builtin")
            plans.append(validate_plan_dict(data))
        except Exception:
            logger.exception("purple_range: bad plan fixture %s (skipped)", name)
    return plans


def load_library_map(directory: str = None) -> Dict[str, Plan]:
    return {p.code: p for p in load_library(directory)}
