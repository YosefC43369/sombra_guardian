"""
osint.sources.hibp — breach exposure lookup via Have I Been Pwned.

SCOPE POSTURE (read this before extending). Per the package README, breach/​
exposure checks in this framework are meant for an organization's OWN assets and
are gated by the command layer behind the repository's authorization tables
(scope_policy / redteam). This source therefore leads with the DOMAIN breach
listing — ``/api/v3/breaches?Domain=<d>`` — which is unauthenticated and returns
the breaches publicly associated with a domain (i.e. "has my org's domain
appeared in a known breach"). It never enumerates or dumps individual private
people's credentials.

Per-account (email) lookup via ``/api/v3/breachedaccount`` DOES require an HIBP
API key and is rate-limited; without ``HIBP_API_KEY`` this source reports
AUTH_REQUIRED for an email target rather than pretending it ran. The password
k-anonymity helper (``pwned_password_count``) needs no key and never sends a
full password or its full hash — only the first five SHA-1 hex chars, per HIBP's
range API.
"""

import re
import hashlib
import logging
from typing import Any, Dict, List, Optional

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.hibp")

import os

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
PWNED_RANGE = "https://api.pwnedpasswords.com/range/"
_UA = "SombraGuardian-OSINT (authorized-assessment)"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _api_key() -> str:
    v = os.getenv("HIBP_API_KEY")
    return v.strip() if v and v.strip() else ""


class HibpSource(Source):
    name = "hibp"
    kind = "domain"
    requires_key = False        # domain path is keyless; email path needs a key

    async def fetch(self, client, target: str) -> SourceResult:
        raw = (target or "").strip()
        if _EMAIL_RE.match(raw):
            return await self._fetch_account(client, raw.lower())
        domain = validators.normalize_domain(raw)
        if domain is None:
            return self._invalid(target, "not a valid domain or email")
        return await self._fetch_domain(client, domain)

    async def _fetch_domain(self, client, domain: str) -> SourceResult:
        result = await client.get(
            f"{HIBP_BASE}/breaches", params={"Domain": domain},
            headers={"User-Agent": _UA})
        if not result.ok:
            if result.status == 429:
                return SourceResult(self.name, domain, SourceStatus.RATE_LIMITED,
                                    reason=result.reason)
            return self._error(domain, result.reason or "HIBP request failed")
        try:
            breaches = result.json()
        except Exception as exc:
            return self._error(domain, f"invalid JSON: {exc}")
        if not isinstance(breaches, list) or not breaches:
            return self._empty(domain, "no known breaches for this domain")

        records: List[Dict[str, Any]] = []
        total_accounts = 0
        for b in breaches:
            if not isinstance(b, dict):
                continue
            name = str(b.get("Name") or b.get("Title") or "").strip()
            if not name:
                continue
            pwn_count = int(b.get("PwnCount") or 0)
            total_accounts += pwn_count
            records.append({
                "type": "breach", "value": name, "source": self.name,
                "breach_date": str(b.get("BreachDate") or ""),
                "pwn_count": pwn_count,
                "data_classes": [str(c) for c in (b.get("DataClasses") or [])],
                "verified": bool(b.get("IsVerified")),
            })
        return SourceResult(
            self.name, domain, SourceStatus.OK, records=records,
            meta={"breach_count": len(records),
                  "accounts_exposed": total_accounts})

    async def _fetch_account(self, client, email: str) -> SourceResult:
        key = _api_key()
        if not key:
            return SourceResult(
                self.name, email, SourceStatus.AUTH_REQUIRED,
                reason="HIBP_API_KEY not set — per-account breach lookup needs a key")
        result = await client.get(
            f"{HIBP_BASE}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "User-Agent": _UA})
        if result.status == 404:
            return self._empty(email, "account not found in any breach")
        if not result.ok:
            if result.status == 401:
                return SourceResult(self.name, email, SourceStatus.AUTH_REQUIRED,
                                    reason="HIBP key rejected")
            if result.status == 429:
                return SourceResult(self.name, email, SourceStatus.RATE_LIMITED,
                                    reason=result.reason)
            return self._error(email, result.reason or "HIBP request failed")
        try:
            breaches = result.json()
        except Exception as exc:
            return self._error(email, f"invalid JSON: {exc}")
        records = [
            {"type": "breach", "value": str(b.get("Name", "")), "source": self.name}
            for b in breaches if isinstance(b, dict) and b.get("Name")
        ]
        if not records:
            return self._empty(email, "account not found in any breach")
        return SourceResult(self.name, email, SourceStatus.OK, records=records,
                            meta={"breach_count": len(records)})


async def pwned_password_count(client, password: str) -> Optional[int]:
    """คืนจำนวนครั้งที่รหัสผ่านนี้ปรากฏในชุดข้อมูลรั่ว (0 = ไม่เจอ) หรือ None ถ้าคิวรีล้ม

    ใช้ k-anonymity: ส่งเฉพาะ 5 ตัวแรกของ SHA-1 hex ไม่เคยส่งรหัสผ่านหรือแฮชเต็ม
    ออกนอกเครื่อง — เซิร์ฟเวอร์คืนช่วงแฮชที่ขึ้นต้นเหมือนกันมาให้เทียบในเครื่อง
    """
    if not password:
        return None
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    result = await client.get(PWNED_RANGE + prefix,
                              headers={"User-Agent": _UA})
    if not result.ok:
        return None
    for line in (result.text or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            try:
                return int(parts[1])
            except ValueError:
                return None
    return 0
