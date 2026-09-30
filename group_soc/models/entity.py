"""
group_soc/models/entity.py — references to the things a security event involves.

An EntityRef is a *privacy-safe* pointer: for a user/bot it holds the salted hash
(and, optionally, a non-sensitive display label an admin already sees in the group),
never a bare re-derivable id in a content field. For a domain/url/hash it holds the
defanged value. Entities are what correlation joins on.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Optional

from ..constants import EntityKind, VALID_ENTITY_KINDS
from ..util import defang, clean_str
from ..constants import MAX_LABEL_LEN


@dataclass(frozen=True)
class EntityRef:
    kind: str                      # EntityKind value
    key: str                       # the join key: actor_hash / etld1 / url-key / etc.
    label: Optional[str] = None    # optional human label (defanged, bounded)

    def __post_init__(self):
        kind = str(self.kind)
        if kind not in VALID_ENTITY_KINDS:
            kind = EntityKind.PATTERN.value
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "key", (str(self.key) if self.key is not None else ""))
        object.__setattr__(self, "label", clean_str(self.label, MAX_LABEL_LEN))

    @property
    def ident(self) -> str:
        """Stable identity string used as a dict key when clustering."""
        return f"{self.kind}:{self.key}"

    def as_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "EntityRef":
        return cls(kind=data.get("kind", EntityKind.PATTERN.value),
                   key=data.get("key", ""), label=data.get("label"))

    @classmethod
    def user(cls, actor_hash: Optional[str], label: Optional[str] = None) -> Optional["EntityRef"]:
        if not actor_hash:
            return None
        return cls(EntityKind.USER.value, actor_hash, label)

    @classmethod
    def domain(cls, value: Optional[str]) -> Optional["EntityRef"]:
        if not value:
            return None
        return cls(EntityKind.DOMAIN.value, defang(str(value).lower()), None)

    @classmethod
    def url(cls, value: Optional[str]) -> Optional["EntityRef"]:
        if not value:
            return None
        return cls(EntityKind.URL.value, defang(str(value)), None)
