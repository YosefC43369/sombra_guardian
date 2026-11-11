# -*- coding: utf-8 -*-
"""red_team_orchestrator/registry.py — ทะเบียนโมดูล + อะแดปเตอร์ + ตัว normalize ผลลัพธ์

ไม่สแกนเอง — เรียก run function "จริง" ของโมดูลที่มีอยู่ (reuse 100%), จับ exception,
แล้วแปลงผลเป็น schema กลาง (ModuleResult + unified finding) โดยคง raw ไว้ใน metadata

unified finding:
  {finding_id, title, description, category, severity, confidence, affected_asset,
   evidence_refs, detection_source, remediation, verification_status, raw}
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("modbot.rt_orch.registry")

# reuse ตัว sanitize เดียวของแพลตฟอร์ม
try:
    from web_vulnerability_assessment.classify import sanitize as _sanitize
except Exception:  # pragma: no cover
    def _sanitize(x, limit=300):
        return (str(x) if x else "")[:limit]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sev_norm(s: str) -> str:
    s = (s or "").upper()
    return s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL") else "INFORMATIONAL"


def finding(detection_source, category, severity, title, description, *, confidence=0.5,
            asset="", evidence="", remediation="", verification="INFORMATIONAL", raw=None,
            idx=0) -> Dict[str, Any]:
    return {
        "finding_id": f"{detection_source}-{idx}",
        "title": title[:160], "description": _sanitize(description, 400),
        "category": category, "severity": _sev_norm(severity),
        "confidence": round(float(confidence), 2), "affected_asset": asset[:200],
        "evidence_refs": [_sanitize(evidence)] if evidence else [],
        "detection_source": detection_source, "remediation": (remediation or "")[:300],
        "verification_status": verification, "raw": raw or {},
    }


def module_result(name, status, findings=None, evidence=None, errors=None,
                  started=None, completed=None, metadata=None) -> Dict[str, Any]:
    return {"module": name, "status": status, "findings": findings or [],
            "evidence": evidence or [], "errors": errors or [],
            "started_at": started, "completed_at": completed, "metadata": metadata or {}}


# ---------------------------------------------------------------------------
# normalizers (ผลโมดูล -> unified findings)
# ---------------------------------------------------------------------------

def _norm_passive(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    cats = report.get("categories", {}) if isinstance(report, dict) else {}
    target = (report.get("target", {}) or {}).get("domain", "")
    for i, r in enumerate((cats.get("security", {}) or {}).get("records", [])):
        out.append(finding("passive_recon", "security_exposure", r.get("severity", "LOW"),
                           r.get("indicator", "exposure indicator"), r.get("detail", ""),
                           confidence=0.4, asset=target, evidence=r.get("indicator", ""),
                           verification="INFORMATIONAL", raw=r, idx=i))
    return out


def _norm_vuln_probe(run: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for i, ind in enumerate(run.get("indicators", []) if isinstance(run, dict) else []):
        out.append(finding("vuln_probe", ind.get("category", "web"), ind.get("severity", "LOW"),
                           ind.get("category", "indicator"), ind.get("detail", ""),
                           confidence=ind.get("confidence", 0.5),
                           asset=run.get("target", ""), evidence=ind.get("evidence", ""),
                           verification="POTENTIAL", raw=ind, idx=i))
    return out


def _norm_findings_schema(assessment: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
    """wva/api ใช้ finding schema เต็มอยู่แล้ว -> map ตรง ๆ"""
    out = []
    for i, f in enumerate(assessment.get("findings", []) if isinstance(assessment, dict) else []):
        out.append(finding(source, f.get("category", "web"), f.get("severity", "LOW"),
                           f.get("rule", f.get("category", "finding")), f.get("detail", ""),
                           confidence=f.get("confidence", 0.5),
                           asset=f.get("endpoint", assessment.get("target", "")),
                           evidence=f.get("evidence", ""), remediation=f.get("recommendation", ""),
                           verification=f.get("state", "INFORMATIONAL"), raw=f, idx=i))
    return out


def _norm_active_scan(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    i = 0
    for h in (scan.get("hosts", []) if isinstance(scan, dict) else []):
        for p in h.get("ports", []):
            out.append(finding("active_scan", "open_port", "INFORMATIONAL",
                               f"open {p['port']}/tcp {p.get('service','')}",
                               f"host {h.get('hostname')} ({h.get('ip')}) port {p['port']} open",
                               confidence=0.9, asset=f"{h.get('ip')}:{p['port']}",
                               evidence=p.get("banner", ""), verification="CONFIRMED",
                               raw=p, idx=i))
            i += 1
    return out


# ---------------------------------------------------------------------------
# adapters (เรียก run function จริง, guarded)
# ---------------------------------------------------------------------------

async def _run_with(coro_factory, name, normalize, metadata_fn=None):
    start = _now()
    try:
        result = await coro_factory()
    except Exception as e:
        logger.exception("RT_ORCH module %s failed", name)
        return module_result(name, "failed", errors=[f"{type(e).__name__}: {e}"],
                             started=start, completed=_now())
    # แยก "ล้มเหลว" ออกจาก "สำเร็จแต่ไม่พบอะไร"
    status = _result_status(result)
    findings = normalize(result) if status in ("completed", "empty") else []
    meta = metadata_fn(result) if metadata_fn else {}
    errs = []
    if isinstance(result, dict):
        errs = [str(e) for e in (result.get("errors") or [])][:10]
        if result.get("denied_reason"):
            status = "failed"
            errs.append(result["denied_reason"])
    return module_result(name, status, findings=findings, errors=errs,
                         started=start, completed=_now(), metadata=meta)


def _result_status(result) -> str:
    if not isinstance(result, dict):
        return "failed"
    st = result.get("status")
    if st in ("denied", "failed", "cancelled"):
        return "failed"
    if result.get("ok") is False:
        return "failed"
    return "completed"


async def adapt_passive(ctx):
    import passive_recon
    return await _run_with(
        lambda: passive_recon.run_recon(ctx["target"], progress=ctx.get("progress")),
        "passive_recon", _norm_passive,
        metadata_fn=lambda r: {"duration_ms": r.get("duration_ms")})


async def adapt_vuln_probe(ctx):
    import vuln_probe
    return await _run_with(
        lambda: vuln_probe.run_probe(ctx["program_id"], ctx["target"], ctx["actor"],
                                     progress=ctx.get("progress")),
        "vuln_probe", _norm_vuln_probe)


async def adapt_wva(ctx):
    import web_vulnerability_assessment as wva
    return await _run_with(
        lambda: wva.run_assessment(ctx["program_id"], ctx["target"], ctx["actor"],
                                   categories=ctx.get("options", {}).get("categories"),
                                   progress=ctx.get("progress")),
        "web_vulnerability_assessment", lambda r: _norm_findings_schema(r, "wva"),
        metadata_fn=lambda r: {"counts": r.get("counts", {})})


async def adapt_api(ctx):
    import api_security_assessment as api
    opts = ctx.get("options", {})
    return await _run_with(
        lambda: api.run_assessment(ctx["program_id"], ctx["target"], ctx["actor"],
                                   spec_text=opts.get("spec_text"), options=opts,
                                   categories=opts.get("categories"),
                                   progress=ctx.get("progress")),
        "api_security_assessment", lambda r: _norm_findings_schema(r, "api"),
        metadata_fn=lambda r: {"endpoints": r.get("endpoints_analyzed", 0),
                               "counts": r.get("counts", {})})


async def adapt_active_scan(ctx):
    import active_scan
    return await _run_with(
        lambda: active_scan.run_scan(ctx["program_id"], ctx["target"], ctx["actor"],
                                     profile=ctx.get("options", {}).get("profile", "quick"),
                                     progress=ctx.get("progress")),
        "active_scan", _norm_active_scan,
        metadata_fn=lambda r: {"summary": r.get("summary", {})})


# ---------------------------------------------------------------------------
# registry + pipelines
# ---------------------------------------------------------------------------

class ModuleSpec:
    def __init__(self, name, kind, requires_program, adapter, available_check):
        self.name = name
        self.kind = kind                  # "passive" | "active"
        self.requires_program = requires_program
        self.adapter = adapter
        self.available_check = available_check


def _avail(mod_name):
    def _check():
        try:
            __import__(mod_name)
            return True
        except Exception:
            return False
    return _check


REGISTRY: Dict[str, ModuleSpec] = {
    "passive_recon": ModuleSpec("passive_recon", "passive", False, adapt_passive,
                                _avail("passive_recon")),
    "vuln_probe": ModuleSpec("vuln_probe", "active", True, adapt_vuln_probe,
                             _avail("vuln_probe")),
    "web_vulnerability_assessment": ModuleSpec("web_vulnerability_assessment", "active", True,
                                               adapt_wva, _avail("web_vulnerability_assessment")),
    "api_security_assessment": ModuleSpec("api_security_assessment", "active", True, adapt_api,
                                          _avail("api_security_assessment")),
    "active_scan": ModuleSpec("active_scan", "active", True, adapt_active_scan,
                              _avail("active_scan")),
}

# pipeline ต่อประเภทงาน (ลำดับ execution + dependency โดยนัย)
PIPELINES: Dict[str, List[str]] = {
    "website_assessment": ["passive_recon", "vuln_probe", "web_vulnerability_assessment"],
    "api_assessment": ["passive_recon", "api_security_assessment"],
    "recon_only": ["passive_recon"],
    "port_scan": ["active_scan"],
}


def available_modules() -> List[str]:
    return [n for n, s in REGISTRY.items() if s.available_check()]


def select_modules(task_type: str, requested: Optional[List[str]] = None) -> List[str]:
    """เลือกโมดูลตามประเภทงาน (หรือรายการที่ร้องขอ) — เฉพาะที่มีจริงและลงทะเบียน"""
    base = PIPELINES.get(task_type, [])
    if requested:
        base = [m for m in requested if m in REGISTRY]
    return [m for m in base if REGISTRY[m].available_check()]
