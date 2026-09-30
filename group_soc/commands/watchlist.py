"""group_soc/commands/watchlist.py — /soc watch / unwatch / watchlist handlers."""

from __future__ import annotations

from typing import List, Optional

from ..exceptions import SocError
from ..constants import EntityKind
from .formatting import bullet_list


def handle_list(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    kind = args[0].lower() if args else None
    entries = rt.watchlist.list(chat_id, kind)
    lines = [f"{e['kind']}:{e['value']}  (sev={e['severity']})" for e in entries]
    return bullet_list(f"👁 Watchlist ({len(entries)})", lines,
                       empty="Watchlist empty. Monitoring a target ≠ a malicious verdict.")


def handle_watch(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    if len(args) < 2:
        return ("ใช้งาน: /soc watch <kind> <value>\nkinds: "
                + ", ".join(k.value for k in EntityKind))
    kind, value = args[0].lower(), " ".join(args[1:])
    try:
        rt.watchlist.add(chat_id, kind, value, added_by_hash=actor_hash)
    except SocError as exc:
        return f"❌ {exc.message}"
    return f"✅ watching {kind}:{value} (monitoring only)"


def handle_unwatch(rt, chat_id: int, actor_hash: Optional[str], args: List[str]) -> str:
    if len(args) < 2:
        return "ใช้งาน: /soc unwatch <kind> <value>"
    kind, value = args[0].lower(), " ".join(args[1:])
    try:
        n = rt.watchlist.remove(chat_id, kind, value, actor_hash)
    except SocError as exc:
        return f"❌ {exc.message}"
    return f"✅ removed {n} watchlist entr{'y' if n == 1 else 'ies'}"
