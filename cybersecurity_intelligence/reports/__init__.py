"""
cybersecurity_intelligence.reports — render finished intelligence for humans.

Every renderer keeps the epistemic separation intact: FACT, SOURCE CLAIM,
ANALYTIC INFERENCE and UNCERTAINTY are shown under their own headings, contradictions
are shown in full (never resolved), and every critical claim is traceable to its
sources. Output formats: Markdown (reports/records), JSON (machine ingestion),
and a compact Telegram-safe text summary.
"""

from __future__ import annotations

from .assessment_report import (
    render_markdown,
    render_json,
    render_telegram,
)

__all__ = ["render_markdown", "render_json", "render_telegram"]
