"""purple_range/exceptions.py — structured exceptions (never silent failures)."""

from __future__ import annotations


class PurpleRangeError(Exception):
    code = "PR_ERROR"

    def __init__(self, message: str = "", *, code: str | None = None, **context):
        super().__init__(message or self.code)
        self.message = message or self.code
        if code:
            self.code = code
        self.context = context

    def __str__(self) -> str:
        base = f"[{self.code}] {self.message}"
        if self.context:
            return base + " (" + ", ".join(f"{k}={v!r}" for k, v in self.context.items()) + ")"
        return base


class PlanValidationError(PurpleRangeError):
    code = "PR_PLAN_INVALID"


class PlanNotFoundError(PurpleRangeError):
    code = "PR_PLAN_NOT_FOUND"


class StorageError(PurpleRangeError):
    code = "PR_STORAGE_ERROR"


class InstantiationError(PurpleRangeError):
    """A plan could not be turned into a purpleteam exercise (delegated call failed)."""
    code = "PR_INSTANTIATION_ERROR"


class IntegrationError(PurpleRangeError):
    code = "PR_INTEGRATION_ERROR"
