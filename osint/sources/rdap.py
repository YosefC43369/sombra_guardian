"""
osint.sources.rdap — registration data (the modern, structured WHOIS) via RDAP.

WHAT / WHY. RDAP (RFC 9082/9083) is the JSON successor to WHOIS: a standardized,
machine-readable way to read who registered a domain or who an IP block is
allocated to, when, through which registrar/RIR, and the domain's current
status (clientTransferProhibited, etc). It is entirely passive — a read of the
public registry — and needs no key. We query rdap.org, the IANA-backed
bootstrap that redirects each query to the authoritative registry/RIR, so a
single URL works for any TLD or address family.

The response is deeply nested; this module flattens the fields an assessment
actually pivots on (registrar, key dates, nameservers, statuses, abuse email)
into flat typed records, and keeps a compact ``meta`` summary for the profile
layer. WHOIS/RDAP anchors accountability for a host on the internet, which is
why it leads the domain workflow.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.rdap")

RDAP_DOMAIN = "https://rdap.org/domain/"
RDAP_IP = "https://rdap.org/ip/"


class RdapSource(Source):
    name = "rdap"
    kind = "domain"          # ก็รับ ip ได้ (ดู _is_ip) — kind หลักคือ domain
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        ip = validators.normalize_ip(target)
        if ip is not None:
            return await self._fetch_ip(client, ip)
        domain = validators.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain or IP")
        return await self._fetch_domain(client, domain)

    async def _fetch_domain(self, client, domain: str) -> SourceResult:
        result = await client.get_json(RDAP_DOMAIN + domain)
        if not result.ok:
            if result.status == 404:
                return self._empty(domain, "no RDAP record (domain not found)")
            if result.status == 429:
                return SourceResult(self.name, domain, SourceStatus.RATE_LIMITED,
                                    reason=result.reason)
            return self._error(domain, result.reason or "RDAP request failed")
        try:
            data = result.json()
        except Exception as exc:
            return self._error(domain, f"invalid JSON: {exc}")
        if not isinstance(data, dict):
            return self._error(domain, "unexpected RDAP shape")

        records: List[Dict[str, Any]] = []
        meta: Dict[str, Any] = {}

        registrar = self._registrar(data)
        if registrar:
            meta["registrar"] = registrar
            records.append({"type": "registrar", "value": registrar,
                            "source": self.name})

        events = self._events(data)
        for kind, date in events.items():
            meta[kind] = date
            records.append({"type": "registration_event", "value": date,
                            "event": kind, "source": self.name})

        statuses = [str(s) for s in (data.get("status") or []) if s]
        if statuses:
            meta["status"] = statuses

        nameservers = self._nameservers(data)
        for ns in nameservers:
            records.append({"type": "hostname", "value": ns, "record": "NS",
                            "source": self.name})
        if nameservers:
            meta["nameservers"] = nameservers

        abuse = self._abuse_email(data)
        if abuse:
            meta["abuse_email"] = abuse
            records.append({"type": "email", "value": abuse, "role": "abuse",
                            "source": self.name})

        if not records:
            return self._empty(domain, "RDAP record had no extractable fields")
        return SourceResult(self.name, domain, SourceStatus.OK, records=records,
                            meta=meta)

    async def _fetch_ip(self, client, ip: str) -> SourceResult:
        result = await client.get_json(RDAP_IP + ip)
        if not result.ok:
            if result.status == 404:
                return self._empty(ip, "no RDAP allocation found")
            return self._error(ip, result.reason or "RDAP request failed")
        try:
            data = result.json()
        except Exception as exc:
            return self._error(ip, f"invalid JSON: {exc}")
        if not isinstance(data, dict):
            return self._error(ip, "unexpected RDAP shape")

        records: List[Dict[str, Any]] = []
        meta: Dict[str, Any] = {}
        name = data.get("name")
        if name:
            meta["netname"] = str(name)
            records.append({"type": "netname", "value": str(name),
                            "source": self.name})
        handle = data.get("handle")
        if handle:
            meta["handle"] = str(handle)
        for key in ("startAddress", "endAddress"):
            if data.get(key):
                meta[key] = str(data[key])
        country = data.get("country")
        if country:
            meta["country"] = str(country)
            records.append({"type": "country", "value": str(country),
                            "source": self.name})
        abuse = self._abuse_email(data)
        if abuse:
            meta["abuse_email"] = abuse
            records.append({"type": "email", "value": abuse, "role": "abuse",
                            "source": self.name})
        if not records:
            return self._empty(ip, "RDAP allocation had no extractable fields")
        return SourceResult(self.name, ip, SourceStatus.OK, records=records,
                            meta=meta)

    # ---------- helpers to flatten RDAP's nested vCard/entity arrays ----------

    @staticmethod
    def _events(data: dict) -> Dict[str, str]:
        """แปลง events[] -> {'registered': date, 'expires': date, ...}"""
        mapping = {
            "registration": "registered",
            "expiration": "expires",
            "last changed": "updated",
            "last update of RDAP database": "rdap_updated",
        }
        out: Dict[str, str] = {}
        for ev in data.get("events") or []:
            if not isinstance(ev, dict):
                continue
            action = str(ev.get("eventAction", "")).lower()
            date = str(ev.get("eventDate", "")).strip()
            key = mapping.get(action)
            if key and date:
                out[key] = date
        return out

    @staticmethod
    def _nameservers(data: dict) -> List[str]:
        out = []
        for ns in data.get("nameservers") or []:
            if isinstance(ns, dict) and ns.get("ldhName"):
                out.append(str(ns["ldhName"]).lower().rstrip("."))
        return sorted(set(out))

    @classmethod
    def _registrar(cls, data: dict) -> Optional[str]:
        for ent in data.get("entities") or []:
            if not isinstance(ent, dict):
                continue
            roles = [str(r).lower() for r in (ent.get("roles") or [])]
            if "registrar" in roles:
                name = cls._vcard_field(ent, "fn")
                if name:
                    return name
        return None

    @classmethod
    def _abuse_email(cls, data: dict) -> Optional[str]:
        """เดินหา entity ที่มี role abuse แล้วดึงอีเมลจาก vCard ของมัน"""
        for ent in cls._iter_entities(data):
            roles = [str(r).lower() for r in (ent.get("roles") or [])]
            if "abuse" in roles:
                email = cls._vcard_field(ent, "email")
                if email:
                    return email
        # ไม่มี role abuse ชัด ๆ — เอาอีเมลแรกที่เจอในเครือ entity
        for ent in cls._iter_entities(data):
            email = cls._vcard_field(ent, "email")
            if email:
                return email
        return None

    @staticmethod
    def _iter_entities(data: dict):
        """ไล่ entities แบบ recursive (RDAP ซ้อน entities ในกันได้)"""
        stack = list(data.get("entities") or [])
        while stack:
            ent = stack.pop()
            if not isinstance(ent, dict):
                continue
            yield ent
            stack.extend(ent.get("entities") or [])

    @staticmethod
    def _vcard_field(entity: dict, field: str) -> Optional[str]:
        """ดึงค่าจาก jCard/vCard array: vcardArray = ["vcard", [ [name, {}, type, value], ...]]"""
        vcard = entity.get("vcardArray")
        if not (isinstance(vcard, list) and len(vcard) == 2
                and isinstance(vcard[1], list)):
            return None
        for item in vcard[1]:
            if isinstance(item, list) and item and item[0] == field:
                value = item[-1]
                if isinstance(value, list):
                    value = " ".join(str(v) for v in value)
                value = str(value).strip()
                if value:
                    return value
        return None
