"""group_soc/commands/alerts.py — /soc alert(s) handlers."""

from __future__ import annotations

from typing import List, Optional

from ..exceptions import SocError
from .formatting import alert_line, alert_detail, bullet_list

_ACTIONS = {"ack": "acknowledge", "acknowledge": "acknowledge", "suppress": "suppress",
            "escalate": "escalate", "resolve": "resolve", "close": "close"}


def handle(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    sub = (args[0].lower() if args else "list")

    if sub in ("list", ""):
        alerts = rt.storage.alerts.list_open(chat_id, limit=20)
        return bullet_list(f"🔔 Open alerts ({len(alerts)})",
                           [alert_line(a) for a in alerts], empty="No open alerts.")

    if sub in _ACTIONS and len(args) >= 2:
        method = getattr(rt.alerts, _ACTIONS[sub])
        try:
            a = method(args[1], actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ alert {a.alert_id} → {a.status}"

    if sub == "assign" and len(args) >= 2:
        assignee = args[2] if len(args) >= 3 else (actor_hash or "")
        try:
            a = rt.alerts.assign(args[1], assignee, actor_hash)
        except SocError as exc:
            return f"❌ {exc.message}"
        return f"✅ alert {a.alert_id} assigned ({a.status})"

    # treat sub as an alert id
    a = rt.storage.alerts.get(args[0])
    if a is None:
        return ("ใช้งาน: /soc alert [list | <id> | ack <id> | suppress <id> | "
                "escalate <id> | resolve <id> | close <id> | assign <id>]")
    return alert_detail(a)
