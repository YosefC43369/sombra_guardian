"""
cve_tracker.telegram.preferences — build/update a chat's subscription from args.

Backs the ``/cve_subscribe`` / ``/cve_unsubscribe`` / ``/cve_preferences``
commands (rule §21). Turns free-form arguments ('critical', 'kev', 'cvss 8',
'vendor microsoft', 'product apache', 'cwe CWE-79', 'keyword rce') into edits on
a :class:`Subscription`, persisted through the repository. Sensible defaults: a
bare ``/cve_subscribe`` subscribes the chat to HIGH+ severity.
"""

from __future__ import annotations

from typing import List, Tuple

from ..enums import Severity
from ..models import Subscription
from ..storage.repository import CVERepository
from ..utils import now_epoch, normalize_cwe_id, dedupe_preserve_order


class SubscriptionService:
    def __init__(self, repo: CVERepository):
        self.repo = repo

    def get(self, chat_id: int, topic_id: int = 0) -> Subscription:
        sub = self.repo.get_subscription(chat_id, topic_id)
        if sub is None:
            sub = Subscription(chat_id=chat_id, topic_id=topic_id or None,
                               min_severity=Severity.HIGH.value)
        return sub

    def subscribe(self, chat_id: int, topic_id: int, args: List[str]) -> Tuple[Subscription, str]:
        """Apply ``args`` to the chat's subscription and persist it. Returns
        (subscription, human_summary)."""
        sub = self.get(chat_id, topic_id)
        sub.enabled = True
        notes = self._apply_args(sub, args)
        sub.updated_at = now_epoch()
        self.repo.upsert_subscription(sub)
        return sub, notes

    def unsubscribe(self, chat_id: int, topic_id: int = 0) -> None:
        sub = self.repo.get_subscription(chat_id, topic_id)
        if sub is not None:
            sub.enabled = False
            sub.updated_at = now_epoch()
            self.repo.upsert_subscription(sub)
        else:
            # create a disabled marker so state is explicit
            self.repo.upsert_subscription(
                Subscription(chat_id=chat_id, topic_id=topic_id or None, enabled=False))

    def _apply_args(self, sub: Subscription, args: List[str]) -> str:
        if not args:
            sub.min_severity = sub.min_severity or Severity.HIGH.value
            return f"รับการแจ้งเตือน CVE ระดับ {sub.min_severity} ขึ้นไป"

        notes: List[str] = []
        i = 0
        while i < len(args):
            tok = args[i].lower()
            if tok in ("critical", "high", "medium", "low"):
                sub.min_severity = tok.upper()
                sub.kev_only = False
                notes.append(f"severity ≥ {tok.upper()}")
            elif tok in ("kev", "known-exploited", "exploited"):
                sub.kev_only = True
                notes.append("เฉพาะ CISA KEV")
            elif tok in ("all", "ทั้งหมด"):
                sub.min_severity = Severity.NONE.value
                sub.kev_only = False
                notes.append("ทุกระดับ")
            elif tok in ("cvss", "score") and i + 1 < len(args):
                try:
                    sub.min_cvss = float(args[i + 1].lstrip(">="))
                    notes.append(f"CVSS ≥ {sub.min_cvss}")
                    i += 1
                except ValueError:
                    pass
            elif tok in ("vendor",) and i + 1 < len(args):
                sub.vendors = dedupe_preserve_order(sub.vendors + [args[i + 1]])
                notes.append(f"vendor={args[i + 1]}")
                i += 1
            elif tok in ("product", "prod") and i + 1 < len(args):
                sub.products = dedupe_preserve_order(sub.products + [args[i + 1]])
                notes.append(f"product={args[i + 1]}")
                i += 1
            elif tok in ("cwe",) and i + 1 < len(args):
                c = normalize_cwe_id(args[i + 1]) or args[i + 1]
                sub.cwes = dedupe_preserve_order(sub.cwes + [c])
                notes.append(f"cwe={c}")
                i += 1
            elif tok in ("keyword", "kw") and i + 1 < len(args):
                sub.keywords = dedupe_preserve_order(sub.keywords + [args[i + 1]])
                notes.append(f"keyword={args[i + 1]}")
                i += 1
            elif tok in ("noupdates", "no-updates"):
                sub.include_updates = False
                notes.append("ไม่รับการอัปเดต CVE")
            elif tok in ("updates",):
                sub.include_updates = True
                notes.append("รับการอัปเดต CVE")
            elif tok in ("noai", "no-ai"):
                sub.ai_summary = False
                notes.append("ไม่ใช้สรุป AI")
            i += 1

        return "; ".join(notes) if notes else "อัปเดตการตั้งค่าแล้ว"

    def describe(self, sub: Subscription) -> str:
        """Human-readable Thai description of a subscription's current filters."""
        if not sub.enabled:
            return "ปิดการแจ้งเตือน CVE อยู่"
        parts = []
        if sub.kev_only:
            parts.append("เฉพาะ CISA KEV")
        else:
            parts.append(f"severity ≥ {sub.min_severity}")
            if sub.min_cvss:
                parts.append(f"CVSS ≥ {sub.min_cvss}")
        if sub.vendors:
            parts.append("vendors: " + ", ".join(sub.vendors))
        if sub.products:
            parts.append("products: " + ", ".join(sub.products))
        if sub.cwes:
            parts.append("CWE: " + ", ".join(sub.cwes))
        if sub.keywords:
            parts.append("keywords: " + ", ".join(sub.keywords))
        parts.append("รับอัปเดต" if sub.include_updates else "ไม่รับอัปเดต")
        return " | ".join(parts)
