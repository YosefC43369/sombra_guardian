"""
entity_fusion.authorization — the fail-closed scope gate for identity fusion.

WHY THIS EXISTS (read before changing anything here). The rest of this engine is
dual-use plumbing: the same code that correlates *your own* organisation's
infrastructure during an authorized red-team engagement could, pointed at an
arbitrary private person, become a de-anonymisation / doxxing tool. The
repository's ``osint`` package already draws this line explicitly — it is
"intentionally NOT a person-profiling / de-anonymization / breach-dossier
pipeline for arbitrary individuals", and person-level work is "gated behind the
repository's existing authorization tables (scope_policy)".

This module is that gate for the fusion engine. It is deliberately conservative:

  * FAIL CLOSED. Anything unrecognised, unconfigured, or ambiguous is DENY.
    There is no code path where a missing program, an unreviewed authorization,
    or an unknown entity type resolves to ALLOW.
  * INFRASTRUCTURE entities (domain / subdomain / ip / url / website /
    certificate) are checked against ``scope_policy.evaluate_target`` — the same
    reviewed-authorization + scope-rule machinery ``/bbscan`` uses. Telegram
    admin is never sufficient (scope_policy has no is_admin parameter, and
    neither does this).
  * PERSON-LEVEL entities (person / username / email / phone / wallet / image)
    require an EXPLICIT, separately-set ``allow_person_scope`` flag on the
    context AND an active, reviewed authorization. Off by default. This flag is
    meant to be turned on only inside a written engagement that covers the
    individuals in question (SOCMINT with consent/authorization, insider-threat
    investigation of your own staff, IR attribution of an actor targeting you).

The gate does not decide policy content — it enforces the policy the operator
already recorded in ``scope_policy``. It records every decision to the shared
audit log when ``security.audit_log`` is available.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .entity import Entity, EntityType

logger = logging.getLogger("modbot.entity_fusion.authz")


# Optional integration with the repo's deterministic policy layer. Imported
# defensively: entity_fusion stays importable (for unit tests of the pure
# correlation code) even in an environment without the policy DB wired up.
try:
    import scope_policy as _scope_policy
    HAVE_SCOPE_POLICY = True
except Exception:  # pragma: no cover - standalone/degraded import
    _scope_policy = None
    HAVE_SCOPE_POLICY = False

try:
    import security as _security
    HAVE_SECURITY = True
except Exception:  # pragma: no cover
    _security = None
    HAVE_SECURITY = False


# Entity types that are treated as infrastructure/asset (checked against
# scope_policy's target scope) vs. person-level (require explicit person scope).
INFRA_TYPES = {
    EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP, EntityType.ASN,
    EntityType.WEBSITE, EntityType.CERTIFICATE, EntityType.ORGANIZATION,
    EntityType.REPOSITORY,
}
PERSON_TYPES = {
    EntityType.PERSON, EntityType.USERNAME, EntityType.EMAIL, EntityType.PHONE,
    EntityType.WALLET, EntityType.IMAGE, EntityType.LOCATION, EntityType.DOCUMENT,
}


class GateReason(str, Enum):
    ALLOWED_INFRA_IN_SCOPE = "ALLOWED_INFRA_IN_SCOPE"
    ALLOWED_PERSON_SCOPE = "ALLOWED_PERSON_SCOPE"
    ALLOWED_DEV_OVERRIDE = "ALLOWED_DEV_OVERRIDE"
    DENY_NO_PROGRAM = "DENY_NO_PROGRAM"
    DENY_NO_SCOPE_POLICY = "DENY_NO_SCOPE_POLICY"
    DENY_OUT_OF_SCOPE = "DENY_OUT_OF_SCOPE"
    DENY_PERSON_SCOPE_DISABLED = "DENY_PERSON_SCOPE_DISABLED"
    DENY_PROGRAM_NOT_AUTHORIZED = "DENY_PROGRAM_NOT_AUTHORIZED"
    DENY_UNKNOWN_TYPE = "DENY_UNKNOWN_TYPE"


@dataclass
class GateDecision:
    allowed: bool
    reason: str
    detail: str = ""
    entity_type: str = ""
    value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed, "reason": self.reason, "detail": self.detail,
            "entity_type": self.entity_type, "value": self.value,
        }


@dataclass
class AuthorizationContext:
    """The authority under which a fusion run executes.

    ``program_id`` is a ``scope_policy`` program with a reviewed authorization.
    ``allow_person_scope`` must be set True *explicitly* by the operator to permit
    correlation of person-level identifiers, and is only honoured when the
    program is itself authorized. ``dev_unsafe_allow_all`` is an escape hatch for
    local development and unit tests ONLY; it logs a loud warning and must never
    be set in a deployed command path.
    """
    program_id: Optional[int] = None
    allow_person_scope: bool = False
    actor: str = ""
    dev_unsafe_allow_all: bool = False

    def __post_init__(self) -> None:
        if self.dev_unsafe_allow_all:
            logger.warning(
                "entity_fusion AuthorizationContext created with "
                "dev_unsafe_allow_all=True — scope enforcement is DISABLED. "
                "This must never be used outside local development/tests.")


class FusionGate:
    """Fail-closed authorization gate. Construct once, reuse across a run."""

    def __init__(self, *, audit: bool = True):
        self.audit = audit

    # -- program-level authorization -------------------------------------- #

    def _program_authorized(self, program_id: Optional[int]) -> Tuple[bool, str]:
        """True only if the program exists, is ACTIVE, and has at least one
        currently-effective reviewed authorization — mirroring evaluate_target's
        preconditions. Fail-closed on any error."""
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
            auths = _scope_policy.list_authorizations(program_id)
            import time as _t
            now = int(_t.time())
            for auth in auths:
                if _scope_policy._authorization_denial_reason(auth, now) is None:
                    return True, "active reviewed authorization present"
            return False, "no effective reviewed authorization"
        except Exception as exc:   # fail closed
            logger.exception("program authorization check failed")
            return False, f"error: {type(exc).__name__}"

    # -- entity-level decision -------------------------------------------- #

    def authorize(self, ctx: AuthorizationContext, entity: Entity) -> GateDecision:
        decision = self._decide(ctx, entity)
        if self.audit:
            self._record(ctx, decision)
        return decision

    def _decide(self, ctx: AuthorizationContext, entity: Entity) -> GateDecision:
        etype = entity.type
        value = entity.value

        if ctx.dev_unsafe_allow_all:
            return GateDecision(True, GateReason.ALLOWED_DEV_OVERRIDE.value,
                                "dev override active", etype.value, value)

        # Unknown type → deny (fail closed).
        if etype not in INFRA_TYPES and etype not in PERSON_TYPES:
            return GateDecision(False, GateReason.DENY_UNKNOWN_TYPE.value,
                                f"type {etype.value} not classifiable", etype.value, value)

        authorized, why = self._program_authorized(ctx.program_id)

        # Infrastructure → defer to scope_policy target evaluation.
        if etype in INFRA_TYPES:
            if not HAVE_SCOPE_POLICY:
                return GateDecision(False, GateReason.DENY_NO_SCOPE_POLICY.value,
                                    "scope_policy unavailable", etype.value, value)
            if ctx.program_id is None:
                return GateDecision(False, GateReason.DENY_NO_PROGRAM.value,
                                    "no program_id supplied", etype.value, value)
            target = self._scope_target(entity)
            if target is None:
                # No scope-checkable target (e.g. ASN/org/repo have no
                # evaluate_target type) — require an authorized program instead
                # of silently allowing.
                if authorized:
                    return GateDecision(True, GateReason.ALLOWED_INFRA_IN_SCOPE.value,
                                        f"program authorized; {etype.value} has no "
                                        f"target-scope check", etype.value, value)
                return GateDecision(False, GateReason.DENY_PROGRAM_NOT_AUTHORIZED.value,
                                    why, etype.value, value)
            try:
                pol = _scope_policy.evaluate_target(ctx.program_id, target)
            except Exception as exc:  # fail closed
                logger.exception("evaluate_target failed")
                return GateDecision(False, GateReason.DENY_OUT_OF_SCOPE.value,
                                    f"policy error: {type(exc).__name__}",
                                    etype.value, value)
            if pol.allowed:
                return GateDecision(True, GateReason.ALLOWED_INFRA_IN_SCOPE.value,
                                    pol.detail or "in scope", etype.value, value)
            return GateDecision(False, GateReason.DENY_OUT_OF_SCOPE.value,
                                f"{pol.reason}: {pol.detail}", etype.value, value)

        # Person-level → require explicit person scope AND an authorized program.
        if not ctx.allow_person_scope:
            return GateDecision(False, GateReason.DENY_PERSON_SCOPE_DISABLED.value,
                                "person-level correlation requires allow_person_scope"
                                " within a written engagement", etype.value, value)
        if not authorized:
            return GateDecision(False, GateReason.DENY_PROGRAM_NOT_AUTHORIZED.value,
                                why, etype.value, value)
        return GateDecision(True, GateReason.ALLOWED_PERSON_SCOPE.value,
                            "person scope explicitly authorized", etype.value, value)

    @staticmethod
    def _scope_target(entity: Entity) -> Optional[str]:
        """Extract a string ``scope_policy.evaluate_target`` can classify
        (DOMAIN/URL/IP/CIDR) from an infrastructure entity, else None."""
        t = entity.type
        if t in (EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP,
                 EntityType.WEBSITE):
            return entity.normalized or entity.value
        return None

    def _record(self, ctx: AuthorizationContext, decision: GateDecision) -> None:
        line = (f"entity_fusion.gate {'ALLOW' if decision.allowed else 'DENY'} "
                f"type={decision.entity_type} reason={decision.reason} "
                f"program={ctx.program_id} actor={ctx.actor!r} "
                f"detail={decision.detail!r}")
        if decision.allowed:
            logger.info(line)
        else:
            logger.warning(line)
        if HAVE_SECURITY and hasattr(_security, "audit_log"):
            try:  # best-effort; never let audit failure change a decision
                _security.audit_log(
                    action="entity_fusion_gate",
                    actor=str(ctx.actor or "system"),
                    detail=line,
                )
            except Exception:
                logger.debug("audit_log write failed (non-fatal)", exc_info=True)

    # -- batch helper ------------------------------------------------------ #

    def partition(self, ctx: AuthorizationContext,
                  entities: List[Entity]) -> Tuple[List[Entity], List[GateDecision]]:
        """Split ``entities`` into (allowed, denied_decisions). The correlation
        pipeline runs on the allowed list only; denials are returned for the
        report so an operator can see what was excluded and why."""
        allowed: List[Entity] = []
        denied: List[GateDecision] = []
        for e in entities:
            d = self.authorize(ctx, e)
            if d.allowed:
                allowed.append(e)
            else:
                denied.append(d)
        return allowed, denied
