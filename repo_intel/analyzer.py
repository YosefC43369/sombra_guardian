# -*- coding: utf-8 -*-
"""
repo_intel.analyzer — ตัวประสานงานวิเคราะห์ repository แบบครบวงจร

ลำดับ: ข้อมูล repo → ลายนิ้วมือ → probe (รันจริงในแซนด์บ็อกซ์) → verdict (จากหลักฐาน)
      → capability analyzers → AI เรียบเรียง → RepoIntelReport

ส่วนที่บล็อก (probe/สแกนไฟล์) รันใน thread; ส่วน AI เป็น async แยก ผู้เรียก (app.py)
await analyze() ได้ตรง ๆ ไม่ผูกกับ scope_policy และไม่อ้างอิงถึงมัน
"""

import asyncio
import logging
from datetime import datetime, timezone

from github_repo import get_repository_info, get_workspace_path
import repository_sandbox as rs

from .model import RepoIntelReport
from . import fingerprint as fp_mod
from . import probe as probe_mod
from . import verdict as verdict_mod
from . import summarize as summarize_mod
from . import capabilities as caps_mod

logger = logging.getLogger("modbot.repo_intel.analyzer")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_label(repository_id) -> str:
    info = get_repository_info(repository_id)
    if info:
        return f"{info.get('owner','?')}/{info.get('name','?')} #{repository_id}"
    return f"repository #{repository_id}"


def analyze_sync(repository_id, actor_user_id=None) -> RepoIntelReport:
    """ทุกอย่างยกเว้น AI (บล็อก I/O + subprocess) — เรียกผ่าน asyncio.to_thread"""
    workspace_path = get_workspace_path(repository_id)
    report = RepoIntelReport(repository_id=repository_id,
                             repo=_repo_label(repository_id),
                             created_at=_now_iso(),
                             fingerprint=fp_mod.Fingerprint())
    if workspace_path is None:
        report.notes.append("ไม่พบเวิร์กสเปซของ repo นี้ (ยังไม่ได้ clone หรือถูกลบ)")
        report.verdict = verdict_mod.decide([])
        return report

    runner, _cmd = rs.detect_test_runner(workspace_path)
    report.fingerprint = fp_mod.build(workspace_path, test_runner=runner,
                                      has_tests=runner is not None)

    # รันจริงในแซนด์บ็อกซ์ → หลักฐาน
    report.evidence = probe_mod.probe_all(repository_id, report.fingerprint, actor_user_id)
    report.verdict = verdict_mod.decide(report.evidence)

    # วิเคราะห์เชิงลึก (สถิต + ตรวจเครื่องมือ)
    ctx = caps_mod.AnalysisContext(repository_id=repository_id,
                                   workspace_path=workspace_path,
                                   fingerprint=report.fingerprint)
    report.capabilities = caps_mod.run_all(ctx)
    return report


async def analyze(repository_id, actor_user_id=None) -> RepoIntelReport:
    """เต็มวงจร: รันส่วนบล็อกใน thread แล้วให้ AI เรียบเรียงจากข้อเท็จจริง"""
    report = await asyncio.to_thread(analyze_sync, repository_id, actor_user_id)
    try:
        summary, provider = await summarize_mod.summarize(report.facts_bundle())
        report.ai_summary = summary
        report.ai_provider = provider
    except Exception:
        logger.exception("repo_intel | สรุปด้วย AI ล้มเหลว — ใช้เทมเพลตแทน")
        report.ai_summary = summarize_mod._fallback(report.facts_bundle())
        report.ai_provider = "template"
    return report
