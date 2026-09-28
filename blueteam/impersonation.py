"""
blueteam/impersonation.py — detect members impersonating admins / VIPs.

Compares a member's display name and username against the group's admins and a
curated VIP list using the confusable *skeleton* (homoglyph/leetspeak/zero-width
folded) plus Jaro-Winkler and Damerau-Levenshtein. A near-match to a protected
identity — by someone who is not that identity — is an impersonation signal, scored
by similarity and explainable.

Checked at three moments (the caller decides which): on join, on name change (using
name history from ``member_intel``), and on first message.

Profile-picture similarity uses a perceptual hash (dHash) **only when Pillow is
installed**; without it the avatar check is skipped silently (กติกา: optional dep,
graceful degrade). No facial recognition — dHash just detects a *reused image*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from . import textkit as tk
from .models import Assessment, Signal

# Similarity above this (Jaro-Winkler on skeletons) counts as a look-alike.
_JW_THRESHOLD = 0.90


@dataclass(slots=True)
class Target:
    """A protected identity (admin or VIP) to compare against."""
    user_id: Optional[int]
    display_name: str = ""
    username: str = ""
    role: str = "admin"


class ImpersonationDetector:
    def __init__(self, store=None):
        self._store = store

    def targets_for(self, chat_id: int,
                    admins: Optional[List[Target]] = None) -> List[Target]:
        """Merge passed-in admins with VIPs stored for the chat."""
        out: List[Target] = list(admins or [])
        if self._store is not None:
            for row in self._store.list_vips(chat_id):
                out.append(Target(
                    user_id=row.get("user_id") or None,
                    display_name=row.get("display_name", ""),
                    username=row.get("username", ""),
                    role=row.get("role", "vip")))
        return out

    def check(self, chat_id: Optional[int], user_id: Optional[int],
              display_name: str, username: str = "", *,
              admins: Optional[List[Target]] = None,
              moment: str = "message") -> Assessment:
        a = Assessment("impersonation", subject=str(user_id or ""))
        targets = self.targets_for(chat_id or 0, admins)
        name_skel = tk.skeleton(display_name or "")
        user_skel = tk.skeleton((username or "").lstrip("@"))
        best: Optional[Tuple[float, Target, str]] = None

        for t in targets:
            # never flag the real identity impersonating itself
            if user_id is not None and t.user_id is not None and t.user_id == user_id:
                return a
            # display-name similarity
            t_name_skel = tk.skeleton(t.display_name or "")
            if name_skel and t_name_skel and len(t_name_skel) >= 3:
                jw = tk.jaro_winkler(name_skel, t_name_skel)
                if jw >= _JW_THRESHOLD:
                    if best is None or jw > best[0]:
                        best = (jw, t, "display_name")
            # username similarity
            t_user_skel = tk.skeleton((t.username or "").lstrip("@"))
            if user_skel and t_user_skel and len(t_user_skel) >= 3:
                jw = tk.jaro_winkler(user_skel, t_user_skel)
                if jw >= _JW_THRESHOLD:
                    if best is None or jw > best[0]:
                        best = (jw, t, "username")

        if best is not None:
            jw, t, field = best
            exact = (field == "display_name" and name_skel == tk.skeleton(t.display_name)) \
                or (field == "username" and user_skel == tk.skeleton((t.username or "").lstrip("@")))
            # exact skeleton match (homoglyph clone) scores higher than a near-miss
            weight = 55 if exact else int(30 + (jw - _JW_THRESHOLD) / (1 - _JW_THRESHOLD) * 20)
            a.add(Signal(
                "impersonation", weight, "impersonation",
                f"{field} เลียนแบบ {t.role} '{t.display_name or t.username}' "
                f"(ความคล้าย {jw:.2f})", "T1656"))
            a.meta.update({"target": t.display_name or t.username, "role": t.role,
                           "similarity": round(jw, 3), "field": field,
                           "moment": moment})
        return a

    # ---- optional perceptual-hash avatar comparison -----------------------
    @staticmethod
    def dhash(image_bytes: bytes, hash_size: int = 8) -> Optional[int]:
        """Difference-hash of an image, or None if Pillow is unavailable/invalid.

        This detects a *reused picture*; it is NOT facial recognition.
        """
        try:
            import io
            from PIL import Image
        except Exception:
            return None
        try:
            img = Image.open(io.BytesIO(image_bytes)).convert("L").resize(
                (hash_size + 1, hash_size), Image.BILINEAR)
        except Exception:
            return None
        bits = 0
        idx = 0
        px = img.load()
        for row in range(hash_size):
            for col in range(hash_size):
                if px[col, row] > px[col + 1, row]:
                    bits |= (1 << idx)
                idx += 1
        return bits

    @classmethod
    def avatar_similar(cls, a_bytes: bytes, b_bytes: bytes,
                       max_distance: int = 6) -> Optional[bool]:
        """True/False if avatars are perceptually similar, or None when Pillow is
        unavailable (caller skips the signal)."""
        ha, hb = cls.dhash(a_bytes), cls.dhash(b_bytes)
        if ha is None or hb is None:
            return None
        return tk.hamming(ha, hb) <= max_distance
