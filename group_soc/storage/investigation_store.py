"""group_soc/storage/investigation_store.py — persistence for investigations + evidence links."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .repository import SocStore
from ..constants import MAX_QUERY_LIMIT
from ..util import now, json_dump, json_load, bounded_limit, clean_str
from ..constants import MAX_REASON_LEN


class InvestigationStore(SocStore):
    # ---- investigations ----
    def add(self, row: Dict[str, Any]) -> None:
        r = dict(row)
        r["hypotheses"] = json_dump(r.get("hypotheses") or [])
        r["findings"] = clean_str(r.get("findings"), MAX_REASON_LEN)
        r["conclusion"] = clean_str(r.get("conclusion"), MAX_REASON_LEN)
        r.setdefault("created_at", now())
        r.setdefault("updated_at", now())
        self._insert("soc_investigations", r)

    def get(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        row = self._get_one("SELECT * FROM soc_investigations WHERE investigation_id=?",
                            (investigation_id,))
        if row:
            row["hypotheses"] = json_load(row.get("hypotheses"))
        return row

    def update(self, investigation_id: str, changes: Dict[str, Any]) -> int:
        changes = dict(changes)
        changes.setdefault("updated_at", now())
        if "hypotheses" in changes and not isinstance(changes["hypotheses"], (str, type(None))):
            changes["hypotheses"] = json_dump(changes["hypotheses"])
        return self._update("soc_investigations", "investigation_id", investigation_id, changes)

    def list_for_chat(self, chat_id: int, limit: int = MAX_QUERY_LIMIT) -> List[Dict[str, Any]]:
        n = bounded_limit(limit, MAX_QUERY_LIMIT, MAX_QUERY_LIMIT)
        rows = self._get_many(
            "SELECT * FROM soc_investigations WHERE chat_id=? ORDER BY updated_at DESC LIMIT ?",
            (int(chat_id), n))
        for r in rows:
            r["hypotheses"] = json_load(r.get("hypotheses"))
        return rows

    # ---- evidence links (generic: owner_kind in case|incident|investigation) ----
    def add_evidence_link(self, chat_id: int, owner_kind: str, owner_id: str,
                          ref_kind: str, ref_id: str, *, note: Optional[str] = None,
                          added_by_hash: Optional[str] = None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO soc_evidence_links (chat_id, owner_kind, owner_id,
                       ref_kind, ref_id, note, added_by_hash, added_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (int(chat_id), owner_kind, owner_id, ref_kind, ref_id,
                 clean_str(note, MAX_REASON_LEN), added_by_hash, now()))
            return cur.lastrowid or 0

    def list_evidence_links(self, owner_kind: str, owner_id: str,
                            limit: int = MAX_QUERY_LIMIT) -> List[Dict[str, Any]]:
        n = bounded_limit(limit, MAX_QUERY_LIMIT, MAX_QUERY_LIMIT)
        return self._get_many(
            "SELECT * FROM soc_evidence_links WHERE owner_kind=? AND owner_id=? "
            "ORDER BY added_at ASC LIMIT ?", (owner_kind, owner_id, n))
