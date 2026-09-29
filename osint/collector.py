"""
osint.collector — the high-level OSINT collection entry point.

Given one validated target this ties the whole passive pipeline together:

    detect kind  ->  select sources  ->  Orchestrator.run (concurrent)
                 ->  profile.build   ->  risk.assess  ->  case record

The result is a single serializable "case" dict: everything an analyst needs,
shaped so it can be shown, redacted for a group, stored, and re-indexed. The
collector performs NO authorization — exactly like every other source path in
this package, the command layer must call ``scope_policy.evaluate_target`` first.
It only collects from the public sources it is handed, against the target it is
handed, and it never raises: a dead source becomes a failed ``SourceResult`` and
the case still assembles from whatever else answered.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .orchestrator import Orchestrator, Intelligence
from .sources.base import Source
from .sources.crtsh import CrtShSource
from .sources.dns_records import DnsRecordsSource
from .sources.rdap import RdapSource
from .sources.site_tech import SiteTechSource
from .sources.hibp import HibpSource
from .sources.google_dork import GoogleDorkSource
from .sources.subfinder import SubfinderSource
from .sources.social import SocialSource, normalize_handle
from .utils import validators
from .utils.async_http import AsyncHTTPClient, HAVE_HTTPX
from . import profile as profile_mod
from . import risk as risk_mod

logger = logging.getLogger("modbot.osint.collector")


def detect_kind(target: str) -> Optional[str]:
    """คืน 'ip' | 'domain' | 'username' ตามรูปแบบ target — None ถ้าไม่เข้าเลย
    ตรวจ ip/domain ก่อน แล้วค่อย username (เช่น @handle) เพื่อไม่ให้โดเมนถูกจับเป็น handle"""
    if validators.normalize_ip(target) is not None:
        return "ip"
    if validators.normalize_domain(target) is not None:
        return "domain"
    if normalize_handle(target) is not None:
        return "username"
    return None


def default_sources(kind: str) -> List[Source]:
    """ชุดแหล่งมาตรฐานต่อชนิดเป้าหมาย — ทั้งหมดเป็นการอ่านข้อมูลสาธารณะล้วน"""
    if kind == "domain":
        return [CrtShSource(), SubfinderSource(), DnsRecordsSource(), RdapSource(),
                SiteTechSource(), HibpSource(), GoogleDorkSource()]
    if kind == "username":
        return [SocialSource()]
    if kind == "ip":
        rdap = RdapSource()
        rdap.kind = "ip"           # RdapSource.fetch รองรับ ip อยู่แล้ว
        srcs: List[Source] = [rdap]
        try:
            from .sources.bgpview import BgpViewSource  # type: ignore
            srcs.append(BgpViewSource())
        except Exception:
            pass
        return srcs
    return []


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _case_id(target: str, merged: List[Dict[str, Any]]) -> str:
    values = sorted(str(m.get("value", "")) for m in merged)
    blob = (target + "\n" + "\n".join(values)).encode("utf-8", "replace")
    sig = hashlib.sha256(blob).hexdigest()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"OSINT-{stamp}-{sig[:8]}", sig


def _source_meta(intel: Intelligence, source_name: str) -> Dict[str, Any]:
    for r in intel.results:
        if r.source == source_name:
            return r.meta or {}
    return {}


def build_case(target: str, kind: str, intel: Intelligence,
               actor: Optional[int] = None) -> Dict[str, Any]:
    """ประกอบ case dict จากผล Intelligence — pure function เทสต์ได้โดยไม่ต่อเน็ต"""
    merged = [m.to_dict() for m in intel.merged]
    case_id, signature = _case_id(target, merged)

    prof = profile_mod.build(merged)
    site_meta = _source_meta(intel, "site_tech")
    hibp_meta = _source_meta(intel, "hibp")
    tech_records = [m for m in merged if m.get("type") == "tech"]
    assessment = risk_mod.assess(site_meta, tech_records, hibp_meta)

    return {
        "schema": "sombra_guardian.osint_case",
        "version": 1,
        "case_id": case_id,
        "signature": signature,
        "target": target,
        "kind": kind,
        "created_at": _now_iso(),
        "collected_by": actor,
        "stats": intel.stats(),
        "assessment": assessment,
        "profile": prof,
        "merged": merged,
        "sources": [
            {"source": r.source, "status": r.status.value, "count": r.count,
             "reason": r.reason, "elapsed_ms": r.elapsed_ms}
            for r in intel.results
        ],
    }


async def collect(target: str, *, actor: Optional[int] = None,
                  sources: Optional[List[Source]] = None,
                  client: Optional[AsyncHTTPClient] = None,
                  concurrency: int = 8,
                  per_source_timeout: float = 30.0,
                  rate: float = 5.0) -> Dict[str, Any]:
    """รันเก็บข่าวกรองแบบเต็มกับ ``target`` แล้วคืน case dict

    ``sources`` ระบุเองได้ (เทสต์/ปรับแต่ง) มิฉะนั้นใช้ default_sources ตามชนิด
    ไม่ตรวจสิทธิ์ — ผู้เรียก (app.py) ต้อง scope_policy.evaluate_target ก่อน
    """
    if not HAVE_HTTPX:
        raise RuntimeError("httpx is required for osint.collect")
    kind = detect_kind(target)
    if kind is None:
        raise ValueError("target must be a domain or IP")

    srcs = sources if sources is not None else default_sources(kind)
    orch = Orchestrator(srcs, concurrency=concurrency,
                        per_source_timeout=per_source_timeout, rate=rate)
    intel = await orch.run(target, kind, client=client)
    case = build_case(target, kind, intel, actor=actor)
    logger.info("OSINT COLLECT | target=%s kind=%s sources=%d merged=%d level=%s",
                target, kind, len(intel.results), len(intel.merged),
                case["assessment"]["security_level"])
    return case
