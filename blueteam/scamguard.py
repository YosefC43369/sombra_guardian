"""
blueteam/scamguard.py — deterministic Thai/English scam detection + campaign
clustering + behavioural signals.

Detection is **deterministic** (no LLM): pre-compiled, ReDoS-linted regex rules
from the versioned packs (:mod:`blueteam.rules`) score a message, each match adding
an explainable :class:`~blueteam.models.Signal` with its category, Thai description
and ATT&CK tag. On top of the lexicon:

  * **Campaign clustering** — a bounded per-chat SimHash ring buffer (LRU across
    chats) flags a message that is near-identical to recent ones from *other*
    senders as part of one campaign (spec: "จับข้อความเกือบซ้ำกันข้ามสมาชิก").
  * **Behavioural signals** — first message after joining contains a link/contact,
    mass @mentions, abnormal posting speed, and the Link Guard verdict folded in.
    These arrive via a ``context`` dict from the plugin (which has the message
    context) so this module stays pure and testable.
  * **Sensitivity presets** — Relaxed / Balanced / Strict shift the verdict
    thresholds to trade recall vs. false positives; an allow-list of phrases and
    exemption of admins/long-standing members further cut false positives.

Reuses the repo's normalization (via :mod:`blueteam.textkit`, which delegates to
``detection.normalize_text``) — no duplicate pipeline.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from . import textkit as tk
from .models import Assessment, Signal, Verdict
from .rules import MAX_SCAN_CHARS, RuleRegistry, get_registry

# Sensitivity -> verdict thresholds (low, suspicious, high, critical).
_SENSITIVITY = {
    "relaxed": (30, 60, 85, 100),
    "balanced": (20, 45, 70, 90),
    "strict": (15, 35, 55, 80),
}


@dataclass(slots=True)
class _CampaignBucket:
    """Bounded ring buffer of recent (simhash, user_id, ts) for one chat."""
    hashes: Deque = field(default_factory=lambda: deque(maxlen=512))


class CampaignTracker:
    """Near-duplicate message clustering across senders, memory-bounded.

    Per-chat ring buffer (size ``buffer``) inside an LRU capped at ``max_chats``
    chats, so total memory is bounded regardless of how many groups are active.
    """

    def __init__(self, buffer: int = 512, max_chats: int = 2000,
                 window_seconds: int = 900, hamming_threshold: int = 8):
        self._buffer = buffer
        self._max_chats = max_chats
        self._window = window_seconds
        self._threshold = hamming_threshold
        self._chats: "OrderedDict[int, _CampaignBucket]" = OrderedDict()

    def _bucket(self, chat_id: int) -> _CampaignBucket:
        b = self._chats.get(chat_id)
        if b is None:
            b = _CampaignBucket(hashes=deque(maxlen=self._buffer))
            self._chats[chat_id] = b
        self._chats.move_to_end(chat_id)
        while len(self._chats) > self._max_chats:
            self._chats.popitem(last=False)
        return b

    def observe(self, chat_id: int, simhash: int, user_id: int,
                now: Optional[float] = None) -> Tuple[int, int]:
        """Record a message and return (cluster_size, distinct_users) for the
        near-duplicate cluster it belongs to (including itself)."""
        now = now if now is not None else time.time()
        bucket = self._bucket(chat_id)
        cutoff = now - self._window
        matches = [(h, u, t) for (h, u, t) in bucket.hashes
                   if t >= cutoff and tk.hamming(h, simhash) <= self._threshold]
        bucket.hashes.append((simhash, user_id, now))
        users = {u for (_h, u, _t) in matches} | {user_id}
        return len(matches) + 1, len(users)


class ScamGuard:
    def __init__(self, store=None, registry: Optional[RuleRegistry] = None,
                 campaign: Optional[CampaignTracker] = None):
        self._registry = registry or get_registry()
        self._store = store
        self._campaign = campaign or CampaignTracker()

    def _thresholds(self, sensitivity: str) -> Tuple[int, int, int, int]:
        return _SENSITIVITY.get((sensitivity or "balanced").lower(),
                                _SENSITIVITY["balanced"])

    def analyze(self, chat_id: Optional[int], text: str, *,
                user_id: Optional[int] = None, sensitivity: str = "balanced",
                context: Optional[dict] = None,
                allow_phrases: Optional[List[str]] = None,
                now: Optional[float] = None) -> Assessment:
        context = context or {}
        thresholds = self._thresholds(sensitivity)
        a = Assessment("scamguard", subject=str(user_id or ""),
                       thresholds=thresholds)

        raw = text or ""
        norm = tk.collapse_thai_tone_marks(tk.normalize(raw))[:MAX_SCAN_CHARS]

        # allow-list phrases: if present, remember and dampen at the end.
        # The phrase must be normalized with the SAME pipeline before comparing —
        # NFKC decomposes some Thai clusters (e.g. SARA AM ำ -> ํา), so a raw phrase
        # would never match the normalized message otherwise.
        allowed_hit = None
        norm_lc = norm.lower()
        raw_lc = raw.lower()
        for phrase in (allow_phrases or []):
            if not phrase:
                continue
            p_norm = tk.collapse_thai_tone_marks(tk.normalize(phrase)).lower()
            if (p_norm and p_norm in norm_lc) or phrase.lower() in raw_lc:
                allowed_hit = phrase
                break

        # 1) deterministic lexicon rules (TH + EN)
        categories = set()
        for rule in self._registry.scam_rules("both"):
            if rule.regex.search(norm) or rule.regex.search(raw):
                a.add(Signal(rule.id, rule.weight, rule.category, rule.desc,
                             rule.attack))
                categories.add(rule.category)
        a.meta["categories"] = sorted(categories)

        # 2) behavioural signals (facts supplied by the caller)
        if context.get("is_first_message") and context.get("has_link_or_contact"):
            a.add(Signal("first_msg_link", 18, "behavioral",
                         "ข้อความแรกหลังเข้ากลุ่มมีลิงก์/ช่องทางติดต่อ", "T1566"))
        mentions = int(context.get("mention_count", 0) or 0)
        if mentions >= 5:
            a.add(Signal("mass_mention", min(20, 6 + 2 * mentions), "behavioral",
                         f"แท็กสมาชิกจำนวนมากพร้อมกัน ({mentions} คน)", "T1566"))
        if float(context.get("post_rate_z", 0) or 0) >= 3.0:
            a.add(Signal("abnormal_rate", 12, "behavioral",
                         "ความเร็วโพสต์สูงผิดปกติเทียบสมาชิกอื่น"))
        link_score = int(context.get("link_score", 0) or 0)
        if link_score >= 45:
            a.add(Signal("malicious_link", min(30, link_score // 2), "link",
                         f"ข้อความมีลิงก์เสี่ยง (คะแนนลิงก์ {link_score})", "T1566.002"))

        # 3) campaign clustering (near-dupe across senders)
        if chat_id is not None and len(norm) >= 8:
            sh = tk.simhash(norm)
            size, users = self._campaign.observe(chat_id, sh, user_id or 0, now)
            a.meta["campaign"] = {"cluster_size": size, "distinct_users": users,
                                  "simhash": sh}
            if size >= 3 and users >= 2:
                a.add(Signal("campaign", min(25, 8 + 4 * users), "campaign",
                             f"ข้อความซ้ำแบบแคมเปญ ({size} ครั้งจาก {users} คน)",
                             "T1566"))

        # 4) exemptions / dampening (false-positive reduction)
        if context.get("is_admin") or context.get("is_trusted"):
            a.meta["exempt"] = "admin_or_trusted"
            # trusted senders: cap at LOW so we monitor but don't act
            a.thresholds = (10, 200, 300, 400)
        if allowed_hit is not None:
            a.meta["allow_phrase"] = allowed_hit
            a.thresholds = (max(a.thresholds[0], 60), 200, 300, 400)
        return a
