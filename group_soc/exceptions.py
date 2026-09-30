"""
group_soc/exceptions.py — the SOC exception hierarchy.

Structured exceptions, never silent failures. Every raise carries a machine
code (for logs/tests) and a human message. Storage/pipeline code catches these
and degrades gracefully; command handlers surface a clean message.
"""

from __future__ import annotations


class SocError(Exception):
    """Base for every SOC-specific error."""

    code = "SOC_ERROR"

    def __init__(self, message: str = "", *, code: str | None = None, **context):
        super().__init__(message or self.code)
        self.message = message or self.code
        if code:
            self.code = code
        self.context = context

    def __str__(self) -> str:
        base = f"[{self.code}] {self.message}"
        if self.context:
            extras = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{base} ({extras})"
        return base


class SocConfigError(SocError):
    code = "SOC_CONFIG_ERROR"


class SocValidationError(SocError):
    """A value handed in by a caller/command failed validation."""
    code = "SOC_VALIDATION_ERROR"


class SocStorageError(SocError):
    """A persistence operation failed."""
    code = "SOC_STORAGE_ERROR"


class SocNotFoundError(SocError):
    """A referenced record does not exist."""
    code = "SOC_NOT_FOUND"


class SocStateError(SocError):
    """An illegal lifecycle transition was requested."""
    code = "SOC_STATE_ERROR"


class SocPipelineError(SocError):
    """A pipeline stage failed in a way the pipeline could not absorb."""
    code = "SOC_PIPELINE_ERROR"


class SocIntegrationError(SocError):
    """An adapter to an external Sombra subsystem failed."""
    code = "SOC_INTEGRATION_ERROR"
