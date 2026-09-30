"""group_soc/commands/incidents.py — /soc incident(s) handlers."""

from __future__ import annotations

from typing import List, Optional

from ..exceptions import SocError
from ..constants import IncidentClass
from ..stories import format_story
from ..timeline import render_timeline
from .formatting import incident_line, bullet_list, hms


def handle(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    sub = (args[0].lower() if args else "list")

    if sub in ("list", ""):
        incs = rt.incidents.list_open(chat_id, limit=20)
        return bullet_list(f"🚨 Open incidents ({len(incs)})",
                           [incident_line(i) for i in incs], empty="No open incidents.")

    if sub == "create" and len(args) >= 3:
        classification = args[1].lower()
        title = " ".join(args[2:])
        try:
            i = rt.incidents.create_manual(chat_id, title, classification,
                                           opened_by_hash=actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ incident {i.incident_id} created ({i.classification})"

    if sub == "resolve" and len(args) >= 2:
        resolution = " ".join(args[2:]) if len(args) >= 3 else ""
        try:
            i = rt.incidents.resolve(args[1], resolution, actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ incident {i.incident_id} → {i.status}"

    if sub == "contain" and len(args) >= 2:
        try:
            i = rt.incidents.contain(args[1], actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ incident {i.incident_id} → {i.status}"

    if sub == "timeline" and len(args) >= 2:
        inc = rt.incidents.get(args[1])
        if inc is None:
            return f"❌ incident not found: {args[1]}"
        entries = rt.timeline.build_for_incident(inc)
        return render_timeline(entries, header=f"TIMELINE {inc.incident_id}")

    if sub == "story" and len(args) >= 2:
        inc = rt.incidents.get(args[1])
        if inc is None:
            return f"❌ incident not found: {args[1]}"
        return format_story(rt.story.for_incident(inc))

    # detail
    inc = rt.incidents.get(args[0])
    if inc is None:
        return ("ใช้งาน: /soc incident [list | <id> | create <class> <title> | "
                "resolve <id> | contain <id> | timeline <id> | story <id>]\n"
                "classes: " + ", ".join(c.value for c in IncidentClass))
    return "\n".join([
        f"Incident {inc.incident_id}",
        f"  title:  {inc.title}",
        f"  class:  {inc.classification}",
        f"  sev:    {inc.severity}",
        f"  status: {inc.status}",
        f"  alerts: {len(inc.alert_ids)}  cases: {len(inc.case_ids)}",
        f"  member_incident_id: {inc.member_incident_id}",
        f"  created: {hms(inc.created_at)}",
    ])
