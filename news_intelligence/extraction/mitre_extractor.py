"""
news_intelligence.extraction.mitre_extractor — ATT&CK technique mining.

Extracts ATT&CK technique identifiers (Txxxx / Txxxx.yyy) directly, and — when the
Threat Actor Intelligence Engine's ATT&CK knowledge base is available — resolves
technique *names* mentioned in prose ("spearphishing attachment", "credential
dumping") back to their technique ids. Reusing the CTI ATT&CK engine avoids a
second, drifting copy of the technique catalog.

Emits ``EntityType.ATTACK_TECHNIQUE`` mentions. Mapping article -> technique feeds
the timeline, graph and the technique-overlap comparison in the vendor engine.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models.entity import EntityMention, EntityType
from .base import BaseExtractor, _mk

_TECH_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")

try:
    from threat_actor_intelligence.mitre.attack_engine import ATTACKEngine
    HAVE_ATTACK = True
except Exception:  # pragma: no cover
    ATTACKEngine = None
    HAVE_ATTACK = False


class MitreExtractor(BaseExtractor):
    name = "mitre"
    entity_types = [EntityType.ATTACK_TECHNIQUE]

    def __init__(self, *, attack: Optional[Any] = None):
        self._attack = attack
        self._name_index: Optional[Dict[str, str]] = None
        if attack is None and HAVE_ATTACK:
            try:
                self._attack = ATTACKEngine().load_seed()
            except Exception:  # pragma: no cover
                self._attack = None

    def _names(self) -> Dict[str, str]:
        """Lowercased technique-name -> id map, built lazily from the ATT&CK KB."""
        if self._name_index is not None:
            return self._name_index
        idx: Dict[str, str] = {}
        atk = self._attack
        if atk is not None:
            try:
                techniques = getattr(atk, "techniques", None)
                items = (techniques.values() if isinstance(techniques, dict)
                         else techniques) or []
                for t in items:
                    tid = getattr(t, "technique_id", "") or getattr(t, "id", "")
                    nm = getattr(t, "name", "")
                    if tid and nm and len(nm) >= 5:
                        idx[nm.lower()] = tid.upper()
            except Exception:  # pragma: no cover
                idx = {}
        self._name_index = idx
        return idx

    def extract(self, text: str, *, article: Optional[Any] = None
                ) -> List[EntityMention]:
        text = text or ""
        out: List[EntityMention] = []
        seen = set()
        for m in _TECH_RE.finditer(text):
            tid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
            tid = tid.upper()
            if tid in seen:
                continue
            seen.add(tid)
            out.append(_mk(EntityType.ATTACK_TECHNIQUE, tid, surface=m.group(0),
                           extractor=self.name, weight=0.95, text=text,
                           span=m.span()))
        names = self._names()
        if names:
            lowered = text.lower()
            for nm, tid in names.items():
                if tid in seen:
                    continue
                pos = lowered.find(nm)
                if pos >= 0:
                    seen.add(tid)
                    out.append(_mk(EntityType.ATTACK_TECHNIQUE, tid,
                                   surface=text[pos:pos + len(nm)],
                                   extractor=self.name + ":name", weight=0.7,
                                   text=text, span=(pos, pos + len(nm)),
                                   detail={"matched_name": nm}))
        return out


__all__ = ["MitreExtractor", "HAVE_ATTACK"]
