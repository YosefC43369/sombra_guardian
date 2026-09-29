"""
cybersecurity_intelligence.exceptions — the package's error hierarchy.

Narrow, specific exceptions so callers (the engine facade, the Telegram layer,
the CLI) can distinguish a configuration problem from a storage failure from a
malformed input without matching on strings. All inherit from ``CTIError`` so a
caller can catch the whole package with one ``except``.
"""

from __future__ import annotations


class CTIError(RuntimeError):
    """Base class for every error raised by the CTI Analysis Engine."""


class CTIConfigError(CTIError):
    """Configuration is missing or invalid (bad path, contradictory settings)."""


class CTIStorageError(CTIError):
    """A persistence operation failed or the schema is inconsistent."""


class CTITransformError(CTIError):
    """An input document could not be transformed into intelligence (malformed
    article, unparseable payload, oversized content)."""


class CTIValidationError(CTIError):
    """A model or value failed an invariant check (e.g. a claim with no
    evidence, an unknown claim type)."""


__all__ = [
    "CTIError",
    "CTIConfigError",
    "CTIStorageError",
    "CTITransformError",
    "CTIValidationError",
]
