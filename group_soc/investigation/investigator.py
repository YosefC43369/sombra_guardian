"""
group_soc/investigation/investigator.py — analyst investigation workspace.

An investigation collects hypotheses, evidence links and pivots around a case. It is a
lightweight state machine (open → active → concluded) over soc_investigations, plus the
pivot helpers in evidence_graph. Every mutation is audited.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..exceptions import SocNotFoundError, SocValidationError
from ..util import gen_id, clean_str, now
from ..constants import MAX_REASON_LEN, MAX_NOTE_LEN
from . import evidence_graph as eg


#: investigation states
OPEN = "open"
ACTIVE = "active"
CONCLUDED = "concluded"
VALID_STATES = frozenset({OPEN, ACTIVE, CONCLUDED})


class Investigator:
    def __init__(self, storage):
        self.storage = storage

    def _load(self, investigation_id: str) -> Dict[str, Any]:
        inv = self.storage.investigations.get(investigation_id)
        if inv is None:
            raise SocNotFoundError("investigation not found", code="SOC_NOT_FOUND",
                                   investigation_id=investigation_id)
        return inv

    def open(self, chat_id: int, title: str, *, case_id: Optional[str] = None,
             opened_by_hash: Optional[str] = None) -> Dict[str, Any]:
        title = clean_str(title, MAX_NOTE_LEN)
        if not title:
            raise SocValidationError("investigation title required", code="SOC_VALIDATION_ERROR")
        iid = gen_id("inv")
        self.storage.investigations.add({
            "investigation_id": iid, "chat_id": int(chat_id), "case_id": case_id,
            "title": title, "state": OPEN, "hypotheses": [], "opened_by_hash": opened_by_hash,
        })
        self.storage.audit(chat_id, "investigation.opened", actor_hash=opened_by_hash,
                           target_kind="investigation", target_id=iid)
        return self._load(iid)

    def add_hypothesis(self, investigation_id: str, text: str,
                       actor_hash: Optional[str] = None) -> Dict[str, Any]:
        inv = self._load(investigation_id)
        text = clean_str(text, MAX_REASON_LEN)
        if not text:
            raise SocValidationError("empty hypothesis", code="SOC_VALIDATION_ERROR")
        hyps = list(inv.get("hypotheses") or [])
        hyps.append({"ts": now(), "text": text})
        self.storage.investigations.update(investigation_id,
                                           {"hypotheses": hyps, "state": ACTIVE})
        self.storage.audit(inv["chat_id"], "investigation.hypothesis_added",
                           actor_hash=actor_hash, target_kind="investigation",
                           target_id=investigation_id)
        return self._load(investigation_id)

    def add_evidence(self, investigation_id: str, ref_kind: str, ref_id: str, *,
                     note: Optional[str] = None, actor_hash: Optional[str] = None) -> int:
        inv = self._load(investigation_id)
        eid = self.storage.investigations.add_evidence_link(
            inv["chat_id"], "investigation", investigation_id, ref_kind, ref_id,
            note=note, added_by_hash=actor_hash)
        self.storage.audit(inv["chat_id"], "investigation.evidence_added",
                           actor_hash=actor_hash, target_kind="investigation",
                           target_id=investigation_id, detail={"ref": f"{ref_kind}:{ref_id}"})
        return eid

    def list_evidence(self, investigation_id: str) -> List[Dict[str, Any]]:
        return self.storage.investigations.list_evidence_links("investigation", investigation_id)

    def conclude(self, investigation_id: str, findings: str, conclusion: str,
                 actor_hash: Optional[str] = None) -> Dict[str, Any]:
        inv = self._load(investigation_id)
        self.storage.investigations.update(investigation_id, {
            "state": CONCLUDED,
            "findings": clean_str(findings, MAX_REASON_LEN),
            "conclusion": clean_str(conclusion, MAX_REASON_LEN),
        })
        self.storage.audit(inv["chat_id"], "investigation.concluded", actor_hash=actor_hash,
                           target_kind="investigation", target_id=investigation_id)
        return self._load(investigation_id)

    # ---- pivots (delegate to evidence_graph) ----
    def pivot_actor(self, chat_id: int, actor_hash: str):
        return eg.pivot_by_actor(self.storage, chat_id, actor_hash)

    def pivot_entity(self, chat_id: int, kind: str, key: str):
        return eg.pivot_by_entity(self.storage, chat_id, kind, key)

    def related(self, chat_id: int, correlation_id: str):
        return eg.related_alerts(self.storage, chat_id, correlation_id)
