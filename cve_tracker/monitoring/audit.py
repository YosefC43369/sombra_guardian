"""
cve_tracker.monitoring.audit — one place to record audit + domain events.

Wraps the repository's audit/event/failure writers with intent-named methods
(rule §49) and optionally forwards domain events to an external emitter (the
platform event bus, wired by the plugin suite). Audit records carry timestamp,
actor, event, CVE and result; they NEVER carry secrets (rule §30/§49).
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("modbot.cve.audit")


class AuditLogger:
    def __init__(self, repo, *, emit=None):
        self.repo = repo
        self.emit = emit

    def _safe(self, fn, *a, **kw):
        try:
            fn(*a, **kw)
        except Exception:
            logger.debug("audit write failed", exc_info=True)

    # ---------------- domain events ----------------

    def event(self, event_type: str, cve_id: str = "", payload: Optional[dict] = None) -> None:
        self._safe(self.repo.log_event, event_type, cve_id, payload or {})
        if self.emit:
            try:
                self.emit(event_type, dict(payload or {}, cve_id=cve_id))
            except Exception:
                pass

    # ---------------- audit operations ----------------

    def source_sync(self, source: str, *, ok: bool, seen: int, new: int,
                    updated: int, error: str = "") -> None:
        self._safe(self.repo.audit, "source_sync", actor=source,
                   result="ok" if ok else "fail",
                   metadata={"seen": seen, "new": new, "updated": updated,
                             "error": error[:200]})

    def cve_created(self, cve_id: str, sources: Optional[list] = None) -> None:
        self._safe(self.repo.audit, "cve_created", cve_id=cve_id,
                   metadata={"sources": sources or []})

    def cve_updated(self, cve_id: str, changes: Optional[list] = None) -> None:
        self._safe(self.repo.audit, "cve_updated", cve_id=cve_id,
                   metadata={"changes": changes or []})

    def ai_summary(self, cve_id: str, *, provider: str, fallback: bool) -> None:
        self._safe(self.repo.audit, "ai_summary_created", cve_id=cve_id,
                   metadata={"provider": provider, "fallback": fallback})

    def notification_sent(self, cve_id: str, chat_id: int) -> None:
        self._safe(self.repo.audit, "notification_sent", cve_id=cve_id,
                   metadata={"chat_id": chat_id})

    def notification_failed(self, cve_id: str, chat_id: int, error: str) -> None:
        self._safe(self.repo.audit, "notification_failed", cve_id=cve_id,
                   result="fail", metadata={"chat_id": chat_id, "error": error[:200]})

    def config_changed(self, actor: str, what: str) -> None:
        self._safe(self.repo.audit, "configuration_changed", actor=actor,
                   metadata={"what": what})

    def failure(self, source: str, cve_id: str, reason: str) -> None:
        self._safe(self.repo.record_failure, source, cve_id, reason)
