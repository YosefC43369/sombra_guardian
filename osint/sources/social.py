"""
osint.sources.social — public social-media presence check for a username/handle.

WHAT / WHY. Given a handle (kind='username'), this checks whether a PUBLIC profile
by that name exists on a set of platforms whose "no such user" path returns a
clean 404 (GitHub, GitLab, Reddit, Keybase, dev.to, Medium, Instagram, TikTok,
Telegram public preview). It reads only the public existence signal — no login,
no scraping of private content, no credential use. Platforms that soft-404
(return 200 for a missing user) are deliberately excluded to keep the signal
honest. Deep per-platform pulls that need an API key (X/Twitter, etc.) are out of
scope here and would be added as their own key-gated sources; this one stays
keyless and safe to run broadly.
"""

import re
import logging
from typing import Dict, List, Optional

from .base import Source, SourceResult, SourceStatus

logger = logging.getLogger("modbot.osint.social")

_HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{2,39}$")

# platform -> (url template, {ok_statuses}, {absent_statuses})
# เลือกเฉพาะแพลตฟอร์มที่ "ไม่พบผู้ใช้" คืน 404 จริง (เลี่ยง soft-404 ที่ทำให้ผลลวง)
_PLATFORMS = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}/about.json",
    "Keybase": "https://keybase.io/{u}",
    "dev.to": "https://dev.to/{u}",
    "Medium": "https://medium.com/@{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Telegram": "https://t.me/{u}",
}


def normalize_handle(raw: str) -> Optional[str]:
    h = (raw or "").strip().lstrip("@")
    return h if _HANDLE_RE.match(h) else None


class SocialSource(Source):
    name = "social"
    kind = "username"
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        handle = normalize_handle(target)
        if handle is None:
            return self._invalid(target, "not a valid username/handle")

        records: List[Dict[str, object]] = []
        checked = 0
        errors = 0
        for platform, template in _PLATFORMS.items():
            url = template.format(u=handle)
            try:
                r = await client.get(url)
            except Exception:
                errors += 1
                continue
            checked += 1
            # 2xx = มีโปรไฟล์สาธารณะ; 404 = ไม่มี; อื่น ๆ = สรุปไม่ได้ (ข้าม)
            if r.status and 200 <= r.status < 300:
                records.append({"type": "profile", "value": url,
                                "platform": platform, "exists": True,
                                "source": self.name})
            elif r.status == 404:
                continue
            else:
                # rate-limited/บล็อก — ไม่ฟันธง เพื่อไม่ให้ผลลวง
                continue

        if errors and not checked:
            return self._error(handle, "all platform checks failed")
        if not records:
            return self._empty(handle, "no public profiles found on checked platforms")
        return SourceResult(self.name, handle, SourceStatus.OK, records=records,
                            meta={"platforms_checked": checked,
                                  "profiles_found": len(records)})
