"""
behavioral_intelligence.reports.executive_summary — a short, decision-maker
summary.

A tight digest of a ``BehaviorProfile``: the headline observed facts, the single
most notable anomaly (framed as deviation-from-baseline), the mean confidence,
and the standing limitations. Kept deliberately brief and label-preserving for a
Telegram message or the top of a longer report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from ..models.behavior import BehaviorProfile
from ..models.confidence import AssertionKind
from ..configuration import PrivacyConfig


def _date(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d") \
        if epoch else "—"


def render(profile: BehaviorProfile, *, privacy: Optional[PrivacyConfig] = None,
           max_points: int = 5) -> str:
    p = profile
    L: List[str] = []
    L.append(f"Behavioral Intelligence — {p.label or p.entity_id or '(entity)'}")
    L.append(f"Period: {_date(p.period_start)} → {_date(p.period_end)} · "
             f"{p.sample_size:,} public observations · "
             f"{len(p.platforms)} platforms")
    L.append("")

    observed = [a for a in p.assertions if a.kind == AssertionKind.OBSERVED]
    for a in observed[:max_points]:
        L.append(f"• {a.statement}")

    if p.languages and p.languages.shares:
        top = sorted(p.languages.shares.items(), key=lambda kv: kv[1], reverse=True)
        L.append("• Language use: " +
                 ", ".join(f"{lang} {share*100:.0f}%" for lang, share in top[:3]))

    if p.anomaly_score:
        L.append(f"• Anomaly score: {p.anomaly_score.score:.0f}/100 "
                 f"({p.anomaly_score.band}) — deviation from own baseline, "
                 f"not a threat score.")

    scored = [a for a in p.assertions if a.confidence]
    if scored:
        mean_conf = sum(a.score for a in scored) / len(scored)
        L.append("")
        L.append(f"Mean confidence: {mean_conf:.2f}")

    L.append("")
    L.append("Limitations: reflects only publicly observed data; describes "
             "activity patterns, not the person; absence of a signal is not "
             "evidence of absence.")
    return "\n".join(L)
