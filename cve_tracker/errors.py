"""
cve_tracker.errors — the subsystem's exception hierarchy.

Design rule (mirrors gemini.ask_gemini / ai_router.route): the *public* entry
points of the subsystem — the background loop, the command handlers, the alert
dispatcher — never let an exception escape into the bot's event loop. These
types exist so internal layers can signal *why* something failed with enough
structure that the retry engine, the source-health tracker and the audit log
can react differently to a transient network blip versus a permanent 4xx.

Every exception carries an optional ``retryable`` hint. The retry engine reads
it first; only when it is ``None`` does it fall back to inspecting the message.
"""

from __future__ import annotations

from typing import Optional


class CVETrackerError(Exception):
    """Root of every error the subsystem raises. Catching this catches all of
    them without also swallowing unrelated ``Exception``s."""

    #: None = 'let the caller decide', True/False = explicit hint.
    retryable: Optional[bool] = None

    def __init__(self, message: str = "", *, retryable: Optional[bool] = None):
        super().__init__(message)
        if retryable is not None:
            self.retryable = retryable


# ---------------- Configuration ----------------

class ConfigError(CVETrackerError):
    """A configuration value is missing or malformed in a way that prevents a
    component from starting. Never retryable."""
    retryable = False


# ---------------- Source / network ----------------

class SourceError(CVETrackerError):
    """Base for anything that goes wrong talking to an external source."""

    def __init__(self, message: str = "", *, source: str = "",
                 retryable: Optional[bool] = None):
        super().__init__(message, retryable=retryable)
        self.source = source


class FetchError(SourceError):
    """A network fetch failed (connection, TLS, DNS). Transient by default."""
    retryable = True


class RateLimitedError(SourceError):
    """The source signalled HTTP 429 / quota exhaustion. Retryable, but the
    retry engine honours ``retry_after`` before trying again."""
    retryable = True

    def __init__(self, message: str = "", *, source: str = "",
                 retry_after: Optional[float] = None):
        super().__init__(message, source=source, retryable=True)
        #: Seconds to wait before the next attempt, from a Retry-After header.
        self.retry_after = retry_after


class TimeoutErrorCVE(SourceError):
    """A request exceeded its per-source timeout budget."""
    retryable = True


class HTTPStatusError(SourceError):
    """A non-2xx response the adapter treats as an error. 5xx is retryable,
    4xx (except 429, which is RateLimitedError) is not."""

    def __init__(self, status: int, message: str = "", *, source: str = ""):
        retryable = status >= 500
        super().__init__(message or f"HTTP {status}", source=source,
                         retryable=retryable)
        self.status = status


class ResponseTooLargeError(SourceError):
    """A response exceeded the configured size ceiling. This is a security
    control (memory-exhaustion / decompression-bomb guard), not a transient
    condition — never retried."""
    retryable = False


# ---------------- Parsing / validation ----------------

class ParseError(CVETrackerError):
    """A source's payload could not be parsed into records. The offending
    batch is skipped; the source is not marked unhealthy for a parse error
    (the bytes arrived fine). Not retryable — the same bytes reparse the same
    way."""
    retryable = False


class ValidationError(CVETrackerError):
    """A normalized record failed a structural/semantic invariant (bad CVE id,
    impossible score, etc.). The record is dropped and counted; other records
    in the batch are unaffected."""
    retryable = False

    def __init__(self, message: str = "", *, field: str = "", value=None):
        super().__init__(message)
        self.field = field
        self.value = value


class NormalizationError(CVETrackerError):
    """A source record could not be mapped onto the normalized model."""
    retryable = False


# ---------------- Storage ----------------

class StorageError(CVETrackerError):
    """Base for database problems."""


class TransientStorageError(StorageError):
    """A sqlite 'database is locked' / busy condition — retry with backoff."""
    retryable = True


class MigrationError(StorageError):
    """Schema is not in the expected shape and could not be reconciled."""
    retryable = False


# ---------------- AI ----------------

class AIError(CVETrackerError):
    """Base for AI-pipeline problems. The subsystem always has a deterministic
    fallback, so these are informational — they downgrade output quality, they
    do not stop a CVE being published."""


class AIUnavailableError(AIError):
    """No AI provider is configured or reachable."""
    retryable = True


class AIValidationError(AIError):
    """The AI produced output that failed hallucination/format validation and
    could not be repaired. The caller falls back to the deterministic
    template."""
    retryable = False


# ---------------- Alerts / Telegram ----------------

class AlertError(CVETrackerError):
    """Base for alert-dispatch problems."""


class FloodControlError(AlertError):
    """Telegram signalled flood control with a ``retry_after``. The throttler
    reschedules the message rather than dropping it."""
    retryable = True

    def __init__(self, message: str = "", *, retry_after: Optional[float] = None):
        super().__init__(message, retryable=True)
        self.retry_after = retry_after


class MessageBuildError(AlertError):
    """A message could not be formatted/split for Telegram. Not retryable —
    the same record formats the same way."""
    retryable = False
