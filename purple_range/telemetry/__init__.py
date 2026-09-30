"""purple_range.telemetry — deterministic synthetic telemetry for detection tuning."""

from .generator import TelemetrySynthesizer
from .templates import build_fields

__all__ = ["TelemetrySynthesizer", "build_fields"]
