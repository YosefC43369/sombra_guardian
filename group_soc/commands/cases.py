"""group_soc/commands/cases.py — /soc case(s) handlers."""

from __future__ import annotations

from typing import List, Optional

from ..exceptions import SocError
from .formatting import case_line, bullet_list, hms


def handle(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    sub = (args[0].lower() if args else "list")

    if sub in ("list", ""):
        cases = rt.cases.list_open(chat_id, limit=20)
        return bullet_list(f"🗂 Open cases ({len(cases)})",
                           [case_line(c) for c in cases], empty="No open cases.")

    if sub == "create" and len(args) >= 2:
        title = " ".join(args[1:])
        try:
            c = rt.cases.create(chat_id, title, opened_by_hash=actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ case created {c.case_id}: {c.title}"

    if sub == "assign" and len(args) >= 2:
        assignee = args[2] if len(args) >= 3 else (actor_hash or "")
        try:
            c = rt.cases.assign(args[1], assignee, actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ case {c.case_id} assigned ({c.status})"

    if sub == "note" and len(args) >= 3:
        try:
            rt.cases.add_note(args[1], " ".join(args[2:]), actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ note added to {args[1]}"

    if sub == "close" and len(args) >= 2:
        try:
            c = rt.cases.close(args[1], actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ case {c.case_id} → {c.status}"

    # detail
    c = rt.cases.get(args[0])
    if c is None:
        return ("ใช้งาน: /soc case [list | <id> | create <title> | assign <id> | "
                "note <id> <text> | close <id>]")
    notes = rt.cases.list_notes(c.case_id)
    lines = [
        f"Case {c.case_id}", f"  title:   {c.title}", f"  status:  {c.status}",
        f"  sev:     {c.severity}", f"  alerts:  {len(c.alert_ids)}",
        f"  created: {hms(c.created_at)}", f"  notes:   {len(notes)}",
    ]
    for n in notes[-5:]:
        lines.append(f"    - [{hms(n.ts)}] {n.text}")
    return "\n".join(lines)
