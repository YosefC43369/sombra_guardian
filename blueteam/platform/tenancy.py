"""
blueteam/platform/tenancy.py — tenant / group / role model (A9).

A **tenant** owns one or more Telegram groups. A single group is, by default, its
own tenant (``tenant_id = "chat:<chat_id>"``) so nothing changes for solo groups.
Roles are ``owner`` > ``admin`` > ``viewer``.

Isolation is enforced at the **repository** layer, not the handler: every repo
method that reads/writes tenant data takes a :class:`TenantScope` and filters on
its ``chat_ids``. :meth:`TenantScope.guard` raises :class:`TenantIsolationError`
if a caller ever passes a chat_id outside the scope — a defence-in-depth tripwire
the cross-tenant tests exercise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable, List, Optional, Sequence, Set


class Role(IntEnum):
    VIEWER = 0
    ADMIN = 1
    OWNER = 2

    @classmethod
    def parse(cls, v) -> "Role":
        if isinstance(v, cls):
            return v
        try:
            return cls[str(v).strip().upper()]
        except KeyError:
            return cls.VIEWER


class TenantIsolationError(PermissionError):
    """Raised when an operation touches a chat outside the active tenant scope."""


def tenant_id_for_chat(chat_id: int) -> str:
    return f"chat:{chat_id}"


@dataclass(frozen=True)
class TenantScope:
    """The set of chats an operation is allowed to touch, plus the actor's role."""

    tenant_id: str
    chat_ids: frozenset
    role: Role = Role.VIEWER
    actor_id: Optional[int] = None

    @classmethod
    def single(cls, chat_id: int, role: Role = Role.ADMIN,
               actor_id: Optional[int] = None) -> "TenantScope":
        return cls(tenant_id_for_chat(chat_id), frozenset({chat_id}), role, actor_id)

    def can(self, required: Role) -> bool:
        return self.role >= required

    def guard(self, chat_id: int) -> int:
        if chat_id not in self.chat_ids:
            raise TenantIsolationError(
                f"chat {chat_id} is outside tenant {self.tenant_id}")
        return chat_id

    def guard_all(self, chat_ids: Iterable[int]) -> List[int]:
        return [self.guard(c) for c in chat_ids]


@dataclass
class Tenant:
    tenant_id: str
    name: str = ""
    chat_ids: Set[int] = field(default_factory=set)
    brand_name: str = ""
    brand_color: str = "#0b3d5c"
    brand_footer: str = ""

    def scope(self, role: Role = Role.OWNER, actor_id: Optional[int] = None) -> TenantScope:
        return TenantScope(self.tenant_id, frozenset(self.chat_ids), role, actor_id)


__all__ = ["Role", "Tenant", "TenantScope", "TenantIsolationError",
           "tenant_id_for_chat"]
