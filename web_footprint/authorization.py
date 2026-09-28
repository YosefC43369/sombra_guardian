"""
web_footprint.authorization — the fail-closed authorization gate and the
scope classifier for passive web-footprint reconnaissance.

Read this before changing anything here.

This engine is dual-use plumbing. Pointed at infrastructure you are authorized
to assess it is a passive attack-surface mapper; pointed at a third party it
would be unsolicited reconnaissance. The rest of this repository draws that line
in code — ``osint`` is "authorized assessment … using PUBLIC information only",
and ``entity_fusion.authorization.FusionGate`` gates every entity against the
reviewed-authorization tables in ``scope_policy``. This module is the equivalent
gate for web-footprint recon, and it is deliberately narrower than FusionGate:
the web-footprint engine is asset/infrastructure-oriented ONLY (domains, hosts,
IPs, URLs, org names, repos). It has no person-level path at all.

Two complementary mechanisms live here:

  * :class:`ReconGate` — MAY this run touch this seed target? Fail-closed:
    unless an authorized ``scope_policy`` program says yes (or an explicit,
    loudly-logged dev override is set for local tests), the answer is DENY. This
    governs whether the engine is *allowed to start* against a seed.
  * :class:`ScopeClassifier` — GIVEN a declared engagement scope (spec §35),
    label each *discovered* asset IN_SCOPE / OUT_OF_SCOPE / UNKNOWN. This is an
    organizational safety feature: it lets an operator see, and later filter,
    which discovered infrastructure falls inside the written scope. It never
    grants authorization by itself — a bug-bounty scope existing does not imply
    permission (spec §34).

Nothing here decides policy content; it enforces the policy an operator already
recorded. Every gate decision is logged, and mirrored to ``security.audit_log``
when available.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .assets import Asset, AssetType, ScopeStatus
from . import normalize

logger = logging.getLogger("modbot.web_footprint.authz")

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


class GateReason(str, Enum):
    ALLOWED_IN_SCOPE = "ALLOWED_IN_SCOPE"
    ALLOWED_DEV_OVERRIDE = "ALLOWED_DEV_OVERRIDE"
    DENY_NO_PROGRAM = "DENY_NO_PROGRAM"
    DENY_NO_SCOPE_POLICY = "DENY_NO_SCOPE_POLICY"
    DENY_OUT_OF_SCOPE = "DENY_OUT_OF_SCOPE"
    DENY_PROGRAM_NOT_AUTHORIZED = "DENY_PROGRAM_NOT_AUTHORIZED"
    DENY_INVALID_TARGET = "DENY_INVALID_TARGET"


@dataclass
class GateDecision:
    allowed: bool
    reason: str
    detail: str = ""
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason,
                "detail": self.detail, "target": self.target}


# --------------------------------------------------------------------------- #
# Declared engagement scope (spec §35)                                         #
# --------------------------------------------------------------------------- #

@dataclass
class ScopeSpec:
    """A declared engagement scope: include/exclude domain patterns.

    Patterns are matched against a hostname. A leading ``*.`` means "this domain
    and any subdomain"; a bare ``example.org`` means "this exact name and its
    subdomains" (the common bug-bounty reading). An exclude match always wins.
    An empty include set means "nothing is positively in scope" — everything
    classifies as UNKNOWN rather than IN_SCOPE, which is the safe default."""

    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)

    @staticmethod
    def _match(pattern: str, host: str) -> bool:
        pat = (pattern or "").strip().lower()
        h = normalize.normalize_domain(host) or (host or "").strip().lower()
        if not pat or not h:
            return False
        if pat.startswith("*."):
            base = pat[2:]
            return normalize.is_subdomain_of(h, base)
        return normalize.is_subdomain_of(h, pat) or h == pat

    def classify_host(self, host: str) -> ScopeStatus:
        if any(self._match(p, host) for p in self.exclude):
            return ScopeStatus.OUT_OF_SCOPE
        if self.include and any(self._match(p, host) for p in self.include):
            return ScopeStatus.IN_SCOPE
        return ScopeStatus.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {"include": list(self.include), "exclude": list(self.exclude)}


class ScopeClassifier:
    """Tag discovered assets IN/OUT/UNKNOWN against a :class:`ScopeSpec`."""

    def __init__(self, scope: Optional[ScopeSpec] = None) -> None:
        self.scope = scope or ScopeSpec()

    def _host_for(self, asset: Asset) -> Optional[str]:
        if asset.subdomain:
            return normalize.normalize_domain(asset.subdomain)
        if asset.domain:
            return normalize.normalize_domain(asset.domain)
        if asset.url:
            return normalize.host_of_url(asset.url)
        if asset.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.WEBSITE):
            return normalize.normalize_domain(asset.value) or normalize.host_of_url(asset.value)
        return None

    def classify(self, asset: Asset) -> ScopeStatus:
        host = self._host_for(asset)
        if host is None:
            return ScopeStatus.UNKNOWN
        return self.scope.classify_host(host)

    def apply(self, assets: List[Asset]) -> None:
        """Set ``asset.scope`` in place for each asset (idempotent)."""
        for a in assets:
            a.scope = self.classify(a)


# --------------------------------------------------------------------------- #
# Run authorization context + gate                                             #
# --------------------------------------------------------------------------- #

@dataclass
class ReconContext:
    """The authority a recon run executes under.

    ``program_id`` names a ``scope_policy`` program that must carry a reviewed,
    currently-effective authorization for the gate to allow anything. ``scope``
    is the declared engagement scope used to *classify* discovered assets (it
    does not, by itself, grant authorization — spec §34). ``dev_unsafe_allow_all``
    disables gating for local development and unit tests ONLY; it logs loudly and
    must never be set in a deployed command path."""

    program_id: Optional[int] = None
    scope: ScopeSpec = field(default_factory=ScopeSpec)
    actor: str = ""
    dev_unsafe_allow_all: bool = False

    def __post_init__(self) -> None:
        if self.dev_unsafe_allow_all:
            logger.warning(
                "web_footprint ReconContext created with dev_unsafe_allow_all=True "
                "— authorization gating is DISABLED. Local development/tests only.")

    def classifier(self) -> ScopeClassifier:
        return ScopeClassifier(self.scope)


class ReconGate:
    """Fail-closed authorization gate for a recon seed target."""

    def __init__(self, *, audit: bool = True) -> None:
        self.audit = audit

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
            now = int(time.time())
            for auth in _scope_policy.list_authorizations(program_id):
                if _scope_policy._authorization_denial_reason(auth, now) is None:
                    return True, "active reviewed authorization present"
            return False, "no effective reviewed authorization"
        except Exception as exc:  # fail closed
            logger.exception("program authorization check failed")
            return False, f"error: {type(exc).__name__}"

    def authorize_seed(self, ctx: ReconContext, target: str) -> GateDecision:
        """May the engine begin recon against ``target``? Fail-closed."""
        decision = self._decide(ctx, target)
        if self.audit:
            self._record(ctx, decision)
        return decision

    def _decide(self, ctx: ReconContext, target: str) -> GateDecision:
        host = (normalize.normalize_domain(target)
                or normalize.host_of_url(target)
                or normalize.normalize_ip(target))
        if not host:
            return GateDecision(False, GateReason.DENY_INVALID_TARGET.value,
                                "target is not a domain/URL/IP", str(target))

        if ctx.dev_unsafe_allow_all:
            return GateDecision(True, GateReason.ALLOWED_DEV_OVERRIDE.value,
                                "dev override active", host)

        if not HAVE_SCOPE_POLICY:
            return GateDecision(False, GateReason.DENY_NO_SCOPE_POLICY.value,
                                "scope_policy unavailable; cannot verify authorization",
                                host)
        if ctx.program_id is None:
            return GateDecision(False, GateReason.DENY_NO_PROGRAM.value,
                                "no program_id supplied", host)

        authorized, why = self._program_authorized(ctx.program_id)
        if not authorized:
            return GateDecision(False, GateReason.DENY_PROGRAM_NOT_AUTHORIZED.value,
                                why, host)
        try:
            pol = _scope_policy.evaluate_target(ctx.program_id, host)
        except Exception as exc:  # fail closed
            logger.exception("evaluate_target failed")
            return GateDecision(False, GateReason.DENY_OUT_OF_SCOPE.value,
                                f"policy error: {type(exc).__name__}", host)
        if getattr(pol, "allowed", False):
            return GateDecision(True, GateReason.ALLOWED_IN_SCOPE.value,
                                getattr(pol, "detail", "") or "in scope", host)
        return GateDecision(False, GateReason.DENY_OUT_OF_SCOPE.value,
                            f"{getattr(pol, 'reason', 'out of scope')}: "
                            f"{getattr(pol, 'detail', '')}", host)

    def _record(self, ctx: ReconContext, decision: GateDecision) -> None:
        line = (f"web_footprint.gate {'ALLOW' if decision.allowed else 'DENY'} "
                f"target={decision.target} reason={decision.reason} "
                f"program={ctx.program_id} actor={ctx.actor!r} "
                f"detail={decision.detail!r}")
        (logger.info if decision.allowed else logger.warning)(line)
        if HAVE_SECURITY and hasattr(_security, "audit_log"):
            try:  # best-effort; never let audit failure change a decision
                _security.audit_log(action="web_footprint_gate",
                                    actor=str(ctx.actor or "system"), detail=line)
            except Exception:
                logger.debug("audit_log write failed (non-fatal)", exc_info=True)
