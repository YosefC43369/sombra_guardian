"""
behavioral_intelligence.authorization — the fail-closed scope gate for
behavioural analysis.

WHY THIS EXISTS (read before changing anything here). This engine aggregates a
person's public activity across time and platforms. Pointed at your own
organisation's assets during an authorized engagement it is threat-hunting and
attribution; pointed at an arbitrary private individual it is surveillance. The
repository already draws this line in code — ``osint`` refuses to be "a
person-profiling / de-anonymization pipeline for arbitrary individuals", and
``entity_fusion.authorization.FusionGate`` gates person-level correlation behind
an explicit flag tied to a reviewed authorization.

This module is the same gate for behaviour. It deliberately delegates to
``entity_fusion``'s ``FusionGate`` when available so there is exactly ONE scope
decision in the codebase, not two that can drift apart. When entity_fusion is
not importable (pure-core / unit-test environments), it falls back to its own
fail-closed logic with identical semantics.

Rules enforced:
  * FAIL CLOSED. Anything unconfigured, unrecognised or ambiguous is DENY.
  * ACCOUNT / PERSON-level behavioural analysis requires an EXPLICIT
    ``allow_person_scope`` flag on the context AND an authorized program. Off by
    default. Meant to be set only inside a written engagement covering the
    accounts in question (authorized SOCMINT, insider-threat of your own staff,
    IR attribution of an actor targeting you).
  * INFRASTRUCTURE behaviour (a domain's public posting cadence, a repo's commit
    rhythm) is checked against the reviewed ``scope_policy`` target scope.
  * ``dev_unsafe_allow_all`` is for local development and tests ONLY; it logs a
    loud warning and must never be set on a deployed command path.

The gate enforces policy the operator already recorded; it does not invent it.
Every decision is written to the shared audit log when available.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("modbot.behavioral.authz")


# Reuse the repo's existing gate so there is a single scope decision. Imported
# defensively: the analytical core must stay importable without the policy DB.
try:
    from entity_fusion.authorization import (
        FusionGate as _FusionGate,
        AuthorizationContext as _FusionCtx,
    )
    from entity_fusion.entity import Entity as _Entity, EntityType as _EntityType
    HAVE_FUSION_GATE = True
except Exception:  # pragma: no cover - standalone/degraded import
    _FusionGate = None  # type: ignore[assignment,misc]
    _FusionCtx = None  # type: ignore[assignment,misc]
    _Entity = None  # type: ignore[assignment,misc]
    _EntityType = None  # type: ignore[assignment,misc]
    HAVE_FUSION_GATE = False

try:
    import scope_policy as _scope_policy
    HAVE_SCOPE_POLICY = True
except Exception:  # pragma: no cover
    _scope_policy = None  # type: ignore[assignment]
    HAVE_SCOPE_POLICY = False

try:
    import security as _security
    HAVE_SECURITY = True
except Exception:  # pragma: no cover
    _security = None  # type: ignore[assignment]
    HAVE_SECURITY = False


class Subject(str, Enum):
    """The kind of thing whose behaviour is being analysed."""
    ACCOUNT = "account"          # a public social account (person-level)
    PERSON = "person"            # a resolved individual (person-level)
    DOMAIN = "domain"            # infrastructure
    REPOSITORY = "repository"    # infrastructure
    ORGANIZATION = "organization"
    IOC = "ioc"                  # a public indicator; infrastructure-level
    UNKNOWN = "unknown"


PERSON_SUBJECTS = {Subject.ACCOUNT, Subject.PERSON}
INFRA_SUBJECTS = {Subject.DOMAIN, Subject.REPOSITORY, Subject.ORGANIZATION,
                  Subject.IOC}


class GateReason(str, Enum):
    ALLOWED_INFRA_IN_SCOPE = "ALLOWED_INFRA_IN_SCOPE"
    ALLOWED_PERSON_SCOPE = "ALLOWED_PERSON_SCOPE"
    ALLOWED_DEV_OVERRIDE = "ALLOWED_DEV_OVERRIDE"
    DENY_NO_PROGRAM = "DENY_NO_PROGRAM"
    DENY_NO_SCOPE_POLICY = "DENY_NO_SCOPE_POLICY"
    DENY_OUT_OF_SCOPE = "DENY_OUT_OF_SCOPE"
    DENY_PERSON_SCOPE_DISABLED = "DENY_PERSON_SCOPE_DISABLED"
    DENY_PROGRAM_NOT_AUTHORIZED = "DENY_PROGRAM_NOT_AUTHORIZED"
    DENY_UNKNOWN_SUBJECT = "DENY_UNKNOWN_SUBJECT"


@dataclass
class GateDecision:
    allowed: bool
    reason: str
    detail: str = ""
    subject: str = ""
    value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason,
                "detail": self.detail, "subject": self.subject, "value": self.value}


@dataclass
class AuthorizationContext:
    """The authority under which a behavioural analysis executes.

    ``program_id`` is a ``scope_policy`` program with a reviewed authorization.
    ``allow_person_scope`` must be set True *explicitly* to permit account/person
    behavioural analysis, and is only honoured when the program is itself
    authorized. ``dev_unsafe_allow_all`` disables enforcement — local dev/tests
    only."""
    program_id: Optional[int] = None
    allow_person_scope: bool = False
    actor: str = ""
    dev_unsafe_allow_all: bool = False

    def __post_init__(self) -> None:
        if self.dev_unsafe_allow_all:
            logger.warning(
                "behavioral_intelligence AuthorizationContext created with "
                "dev_unsafe_allow_all=True — scope enforcement is DISABLED. "
                "This must never be used outside local development/tests.")

    def to_fusion(self) -> Any:
        """Project onto entity_fusion's context so the shared gate can decide."""
        if not HAVE_FUSION_GATE:
            return None
        return _FusionCtx(program_id=self.program_id,
                          allow_person_scope=self.allow_person_scope,
                          actor=self.actor,
                          dev_unsafe_allow_all=self.dev_unsafe_allow_all)


# Map a behavioural Subject onto the entity_fusion EntityType used by the shared
# gate, so a single policy governs both engines.
_SUBJECT_TO_ETYPE = {
    Subject.ACCOUNT: "username",
    Subject.PERSON: "person",
    Subject.DOMAIN: "domain",
    Subject.REPOSITORY: "repository",
    Subject.ORGANIZATION: "organization",
    Subject.IOC: "domain",       # an IOC target is scope-checked as infrastructure
}


class BehaviorGate:
    """Fail-closed authorization gate for behavioural analysis.

    Prefers the shared ``entity_fusion`` gate; falls back to identical local
    logic when that package is unavailable. Construct once, reuse across a run."""

    def __init__(self, *, audit: bool = True):
        self.audit = audit
        self._fusion = _FusionGate(audit=False) if HAVE_FUSION_GATE else None

    def authorize(self, ctx: AuthorizationContext, subject: Subject,
                  value: str) -> GateDecision:
        decision = self._decide(ctx, subject, value)
        if self.audit:
            self._record(ctx, decision)
        return decision

    def _decide(self, ctx: AuthorizationContext, subject: Subject,
                value: str) -> GateDecision:
        subject = subject if isinstance(subject, Subject) else Subject(str(subject))

        if ctx.dev_unsafe_allow_all:
            return GateDecision(True, GateReason.ALLOWED_DEV_OVERRIDE.value,
                                "dev override active", subject.value, value)

        if subject not in PERSON_SUBJECTS and subject not in INFRA_SUBJECTS:
            return GateDecision(False, GateReason.DENY_UNKNOWN_SUBJECT.value,
                                f"subject {subject.value} not classifiable",
                                subject.value, value)

        # Delegate to the shared gate when present — one decision for the repo.
        if self._fusion is not None:
            etype = _EntityType.coerce(_SUBJECT_TO_ETYPE.get(subject, "unknown"))
            entity = _Entity(type=etype, value=value)
            d = self._fusion.authorize(ctx.to_fusion(), entity)
            return GateDecision(d.allowed, d.reason, d.detail, subject.value, value)

        # ---- fallback: local fail-closed logic (identical semantics) ---- #
        authorized, why = self._program_authorized(ctx.program_id)
        if subject in INFRA_SUBJECTS:
            if not HAVE_SCOPE_POLICY:
                return GateDecision(False, GateReason.DENY_NO_SCOPE_POLICY.value,
                                    "scope_policy unavailable", subject.value, value)
            if ctx.program_id is None:
                return GateDecision(False, GateReason.DENY_NO_PROGRAM.value,
                                    "no program_id supplied", subject.value, value)
            target = value if subject in (Subject.DOMAIN, Subject.IOC) else None
            if target is None:
                if authorized:
                    return GateDecision(True, GateReason.ALLOWED_INFRA_IN_SCOPE.value,
                                        f"program authorized; {subject.value} has no "
                                        f"target-scope check", subject.value, value)
                return GateDecision(False, GateReason.DENY_PROGRAM_NOT_AUTHORIZED.value,
                                    why, subject.value, value)
            try:
                pol = _scope_policy.evaluate_target(ctx.program_id, target)
            except Exception as exc:   # fail closed
                logger.exception("evaluate_target failed")
                return GateDecision(False, GateReason.DENY_OUT_OF_SCOPE.value,
                                    f"policy error: {type(exc).__name__}",
                                    subject.value, value)
            if pol.allowed:
                return GateDecision(True, GateReason.ALLOWED_INFRA_IN_SCOPE.value,
                                    pol.detail or "in scope", subject.value, value)
            return GateDecision(False, GateReason.DENY_OUT_OF_SCOPE.value,
                                f"{pol.reason}: {pol.detail}", subject.value, value)

        # person-level
        if not ctx.allow_person_scope:
            return GateDecision(False, GateReason.DENY_PERSON_SCOPE_DISABLED.value,
                                "account/person behavioural analysis requires "
                                "allow_person_scope within a written engagement",
                                subject.value, value)
        if not authorized:
            return GateDecision(False, GateReason.DENY_PROGRAM_NOT_AUTHORIZED.value,
                                why, subject.value, value)
        return GateDecision(True, GateReason.ALLOWED_PERSON_SCOPE.value,
                            "person scope explicitly authorized", subject.value, value)

    def _program_authorized(self, program_id: Optional[int]) -> Tuple[bool, str]:
        if program_id is None:
            return False, "no program_id"
        if not HAVE_SCOPE_POLICY:
            return False, "scope_policy unavailable"
        try:
            program = _scope_policy.get_program(program_id)
            if not program:
                return False, f"program {program_id} not found"
            if program.get("status") != _scope_policy.ProgramStatus.ACTIVE.value:
                return False, f"program status={program.get('status')}"
            import time as _t
            now = int(_t.time())
            for auth in _scope_policy.list_authorizations(program_id):
                if _scope_policy._authorization_denial_reason(auth, now) is None:
                    return True, "active reviewed authorization present"
            return False, "no effective reviewed authorization"
        except Exception as exc:   # fail closed
            logger.exception("program authorization check failed")
            return False, f"error: {type(exc).__name__}"

    def _record(self, ctx: AuthorizationContext, decision: GateDecision) -> None:
        line = (f"behavioral.gate {'ALLOW' if decision.allowed else 'DENY'} "
                f"subject={decision.subject} reason={decision.reason} "
                f"program={ctx.program_id} actor={ctx.actor!r} "
                f"detail={decision.detail!r}")
        (logger.info if decision.allowed else logger.warning)(line)
        if HAVE_SECURITY and hasattr(_security, "audit_log"):
            try:
                _security.audit_log(action="behavioral_gate",
                                    actor=str(ctx.actor or "system"), detail=line)
            except Exception:
                logger.debug("audit_log write failed (non-fatal)", exc_info=True)


def require(ctx: AuthorizationContext, subject: Subject, value: str,
            *, gate: Optional[BehaviorGate] = None) -> GateDecision:
    """Authorize or raise. Engines that must not run outside scope call this at
    their entry point; a denied decision raises ``PermissionError`` carrying the
    reason so the caller reports *why* rather than silently returning empty."""
    g = gate or BehaviorGate()
    d = g.authorize(ctx, subject, value)
    if not d.allowed:
        raise PermissionError(f"behavioral scope denied [{d.reason}]: {d.detail}")
    return d
