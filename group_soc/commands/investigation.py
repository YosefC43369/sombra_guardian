"""group_soc/commands/investigation.py — /soc investigate / pivot handlers."""

from __future__ import annotations

from typing import List, Optional

from ..exceptions import SocError
from .formatting import bullet_list


def handle(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    sub = (args[0].lower() if args else "list")

    if sub in ("list", ""):
        invs = rt.storage.investigations.list_for_chat(chat_id, limit=20)
        lines = [f"{i['investigation_id']}  {i['title']}  ({i['state']})" for i in invs]
        return bullet_list(f"🔬 Investigations ({len(invs)})", lines, empty="No investigations.")

    if sub == "open" and len(args) >= 2:
        try:
            inv = rt.investigator.open(chat_id, " ".join(args[1:]), opened_by_hash=actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ investigation opened {inv['investigation_id']}"

    if sub == "hypothesis" and len(args) >= 3:
        try:
            rt.investigator.add_hypothesis(args[1], " ".join(args[2:]), actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ hypothesis added to {args[1]}"

    if sub == "evidence" and len(args) >= 4:
        # evidence <inv_id> <ref_kind> <ref_id>
        try:
            rt.investigator.add_evidence(args[1], args[2], args[3], actor_hash=actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ evidence linked to {args[1]}"

    if sub == "conclude" and len(args) >= 3:
        try:
            rt.investigator.conclude(args[1], " ".join(args[2:]), " ".join(args[2:]), actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ investigation {args[1]} concluded"

    # detail
    inv = rt.storage.investigations.get(args[0])
    if inv is None:
        return ("ใช้งาน: /soc investigate [list | open <title> | hypothesis <id> <text> | "
                "evidence <id> <kind> <ref> | conclude <id> <text>]")
    lines = [f"Investigation {inv['investigation_id']}", f"  title: {inv['title']}",
             f"  state: {inv['state']}"]
    for h in (inv.get("hypotheses") or [])[-5:]:
        lines.append(f"  hyp: {h.get('text')}")
    ev = rt.investigator.list_evidence(inv["investigation_id"])
    lines.append(f"  evidence links: {len(ev)}")
    return "\n".join(lines)


def handle_pivot(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    if len(args) < 2:
        return "ใช้งาน: /soc pivot [actor <hash> | entity <kind> <key> | related <correlation_id>]"
    mode = args[0].lower()
    if mode == "actor":
        evs = rt.investigator.pivot_actor(chat_id, args[1])
        return bullet_list(f"actor pivot ({len(evs)} events)",
                           [f"{e.event_type} @ {e.ts}" for e in evs[:20]])
    if mode == "entity" and len(args) >= 3:
        evs = rt.investigator.pivot_entity(chat_id, args[1], args[2])
        return bullet_list(f"entity pivot ({len(evs)} events)",
                           [f"{e.event_type} @ {e.ts}" for e in evs[:20]])
    if mode == "related":
        alerts = rt.investigator.related(chat_id, args[1])
        return bullet_list(f"related alerts ({len(alerts)})",
                           [a.title for a in alerts[:20]])
    return "ใช้งาน: /soc pivot [actor <hash> | entity <kind> <key> | related <correlation_id>]"
