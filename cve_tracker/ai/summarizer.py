"""
cve_tracker.ai.summarizer — orchestrate fact → validated Thai summary.

The pipeline (rules §13–§16):

    cache lookup → (miss) build prompt → call AI → validate → repair/retry
                 → build AISummary            │
                 └──────────────── fallback ──┘ (AI down, or validation fails)

The summarizer returns an :class:`AISummary` carrying the Thai text fields
(title/summary/impact/recommendation) and its provenance/state. It does NOT
assemble the final Telegram message — the alerts formatter does that from the
record + this summary — so there is no circular dependency and one place owns
message layout. When the AI is unavailable or its output can't be validated, the
summary is marked ``fallback_used`` and its recommendations are seeded from the
deterministic analyzer, so the caller can always publish something factual.
"""

from __future__ import annotations

import logging
from typing import Optional

from ..enums import AIProcessingState
from ..models import AISummary, CVERecord
from ..utils import now_epoch
from .adapter import AIProviderAdapter, AIResult
from .cache import AISummaryCache
from . import analyzer
from . import prompt_builder
from .validator import validate

logger = logging.getLogger("modbot.cve.summarizer")


class CVESummarizer:
    def __init__(self, ai_config, *, repo=None, adapter: Optional[AIProviderAdapter] = None):
        self.config = ai_config
        self.adapter = adapter or AIProviderAdapter(ai_config)
        self.cache = AISummaryCache(repo, ttl=ai_config.cache_ttl)

    async def summarize(self, record: CVERecord) -> AISummary:
        input_hash = prompt_builder.input_signature(record)

        cached = self.cache.get(record.cve_id, input_hash)
        if cached is not None:
            return cached

        if not self.config.enabled:
            return self._fallback(record, input_hash,
                                  state=AIProcessingState.SKIPPED.value)
        if not self.adapter.available():
            return self._fallback(record, input_hash,
                                  state=AIProcessingState.UNAVAILABLE.value)

        system = prompt_builder.SYSTEM_INSTRUCTION
        prompt = prompt_builder.build_prompt(record)

        attempts = max(1, self.config.max_repair_attempts + 1)
        last_problems = []
        for i in range(attempts):
            res: AIResult = await self.adapter.generate(prompt, system=system, task="heavy")
            if not res.ok:
                logger.info("CVE AI generate failed (%s) for %s", res.reason, record.cve_id)
                break  # provider failure → fallback (retrying won't help this round)
            report = validate(record, res.text)
            if report.ok:
                return self._from_validated(record, input_hash, report.data, res)
            last_problems = report.problems
            logger.info("CVE AI validation failed for %s: %s (attempt %d)",
                        record.cve_id, ",".join(report.problems), i + 1)
            # On the next attempt, nudge the model with the specific problem.
            prompt = prompt_builder.build_prompt(record) + (
                "\n\nหมายเหตุ: คำตอบก่อนหน้ามีปัญหา ("
                + ", ".join(report.problems[:3])
                + ") กรุณาตอบใหม่โดยใช้เฉพาะข้อเท็จจริงใน STRUCTURED_FACTS")

        return self._fallback(record, input_hash,
                              state=AIProcessingState.FALLBACK.value,
                              problems=last_problems)

    # ---------------- builders ----------------

    def _from_validated(self, record: CVERecord, input_hash: str,
                        data: dict, res: AIResult) -> AISummary:
        recs = analyzer.merge_recommendations(
            list(data.get("recommendation_th") or []), record)
        summary = AISummary(
            cve_id=record.cve_id,
            language=self.config.language,
            title_th=str(data.get("title_th", "") or "").strip() or record.title,
            summary_th=str(data.get("summary_th", "") or "").strip(),
            impact_th=str(data.get("impact_th", "") or "").strip() or analyzer.impact_sentence(record),
            recommendation_th="\n".join(recs),
            provider=res.provider,
            model=res.model,
            state=AIProcessingState.DONE.value,
            validated=True,
            fallback_used=False,
            created_at=now_epoch(),
            input_hash=input_hash,
        )
        self.cache.put(summary)
        return summary

    def _fallback(self, record: CVERecord, input_hash: str, *,
                  state: str, problems=None) -> AISummary:
        """Deterministic, fact-only summary. Not cached (so a recovered AI is
        used next time). Thai text comes from the analyzer + the original
        title/description — no fabrication."""
        recs = analyzer.recommendations(record)
        summary_th = (record.description or "").strip()
        return AISummary(
            cve_id=record.cve_id,
            language=self.config.language,
            title_th=analyzer.title_fallback(record),
            summary_th=summary_th,
            impact_th=analyzer.impact_sentence(record),
            recommendation_th="\n".join(recs),
            provider="",
            model="",
            state=state,
            validated=False,
            fallback_used=True,
            created_at=now_epoch(),
            input_hash=input_hash,
        )
