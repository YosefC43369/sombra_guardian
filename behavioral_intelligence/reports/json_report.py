"""
behavioral_intelligence.reports.json_report — machine-readable report.

Serialises a ``BehaviorProfile`` to JSON with a small envelope (schema version,
generation time, the standing epistemic disclaimer) so downstream systems get the
full structured result — every assertion with its kind, confidence, evidence and
limitations intact.
"""

from __future__ import annotations

import json
import time
from typing import Optional

from ..models.behavior import BehaviorProfile
from ..configuration import PrivacyConfig

SCHEMA_VERSION = "behavioral-intelligence/1.0"


def render(profile: BehaviorProfile, *, privacy: Optional[PrivacyConfig] = None,
           indent: int = 2) -> str:
    envelope = {
        "schema": SCHEMA_VERSION,
        "generated_at": time.time(),
        "disclaimer": ("Describes observable public activity patterns only. No "
                       "psychological, medical, criminal-intent, ideological or "
                       "identity conclusion is implied. Every finding carries its "
                       "epistemic kind (OBSERVED/CORRELATED/INFERRED/UNKNOWN), "
                       "confidence and limitations."),
        "profile": profile.to_dict(),
    }
    return json.dumps(envelope, ensure_ascii=False, indent=indent, sort_keys=False)
