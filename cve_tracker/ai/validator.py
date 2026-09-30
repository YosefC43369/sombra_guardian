"""
cve_tracker.ai.validator — guard AI output against hallucination before send.

Rule §15: before an AI summary reaches Telegram it is checked against the
structured facts. We catch the failure modes that actually happen with LLMs on
this task:

  * a *different* CVE id appears in the text (id confusion)
  * a CVSS number is asserted that the facts don't contain (fabricated score)
  * a KEV / 'exploited' claim when facts say KEV=false (over-claiming)
  * output too long for Telegram, or malformed/empty JSON

The validator first tries cheap **repair** (strip stray ids, truncate), and only
when a claim can't be reconciled does it fail — the caller then falls back to the
deterministic template (rule §15 step 3). It never 'fixes' by inventing; it only
removes/limits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models import CVERecord
from ..utils import extract_cve_ids, safe_json_loads, truncate
from ..constants import MAX_AI_SUMMARY_CHARS

_CVSS_MENTION_RE = re.compile(r"cvss[^0-9]{0,8}(\d{1,2}(?:\.\d)?)", re.I)
_BARE_SCORE_RE = re.compile(r"\b(?:คะแนน|score)\D{0,6}(\d{1,2}\.\d)\b", re.I)
_KEV_CLAIM_RE = re.compile(r"(ถูกใช้โจมตีจริง|exploited in the wild|อยู่ใน\s*kev|known exploited)", re.I)


@dataclass
class ValidationReport:
    ok: bool
    data: Dict[str, object] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)
    repaired: bool = False


def _known_scores(record: CVERecord) -> set:
    scores = set()
    for s in record.cvss_scores:
        if s.base_score is not None:
            scores.add(f"{float(s.base_score):.1f}")
            scores.add(str(int(s.base_score)) if float(s.base_score).is_integer() else "")
    if record.cvss_score is not None:
        scores.add(f"{float(record.cvss_score):.1f}")
    scores.discard("")
    return scores


def validate(record: CVERecord, raw_text: str) -> ValidationReport:
    """Validate (and lightly repair) the model's JSON output for ``record``."""
    data = safe_json_loads(raw_text, default=None)
    if not isinstance(data, dict):
        return ValidationReport(False, problems=["not-json"])

    report = ValidationReport(True, data=data)

    # Required textual field.
    summary = str(data.get("summary_th", "") or "").strip()
    if not summary:
        report.ok = False
        report.problems.append("empty-summary")
        return report

    # --- CVE id confusion ---
    valid_ids = {record.cve_id} | set(record.aliases)
    for field_name in ("title_th", "summary_th", "impact_th"):
        val = str(data.get(field_name, "") or "")
        stray = [cid for cid in extract_cve_ids(val) if cid not in valid_ids]
        if stray:
            # Repair: strip the wrong id rather than reject outright.
            for cid in stray:
                val = val.replace(cid, record.cve_id)
            data[field_name] = val
            report.repaired = True
            report.problems.append(f"stray-cve-id-repaired:{','.join(stray)}")

    # --- fabricated CVSS ---
    known = _known_scores(record)
    joined = " ".join(str(data.get(k, "")) for k in ("summary_th", "impact_th", "title_th"))
    mentioned = set(_CVSS_MENTION_RE.findall(joined)) | set(_BARE_SCORE_RE.findall(joined))
    for m in mentioned:
        norm = f"{float(m):.1f}" if "." in m else m
        if norm not in known and m not in known:
            # A CVSS number not in the facts → fabrication; unrepairable.
            report.ok = False
            report.problems.append(f"fabricated-cvss:{m}")
    # --- over-claiming KEV/exploited ---
    if not record.in_kev and _KEV_CLAIM_RE.search(joined) and record.exploit_maturity not in (
            "confirmed",):
        report.ok = False
        report.problems.append("unsupported-exploited-claim")

    # --- length ---
    for field_name in ("summary_th", "impact_th"):
        val = str(data.get(field_name, "") or "")
        if len(val) > MAX_AI_SUMMARY_CHARS:
            data[field_name] = truncate(val, MAX_AI_SUMMARY_CHARS)
            report.repaired = True
            report.problems.append(f"{field_name}-truncated")

    # Normalise recommendation to a list of clean strings.
    recs = data.get("recommendation_th")
    if isinstance(recs, str):
        data["recommendation_th"] = [recs.strip()] if recs.strip() else []
    elif isinstance(recs, list):
        data["recommendation_th"] = [str(x).strip() for x in recs if str(x).strip()][:6]
    else:
        data["recommendation_th"] = []

    report.data = data
    return report
