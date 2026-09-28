"""
behavioral_intelligence.reports.evidence_report — the evidence table (spec §31).

Every analytical output in this engine links back to evidence. This report walks
a ``BehaviorProfile``'s assertions and emits the evidence behind each: provider,
source URL, observation id, content hash, timestamp, collection time and the
source's self-reported confidence — so a reviewer can audit the chain from a
conclusion back to the public data it rests on.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from ..models.behavior import BehaviorProfile
from ..configuration import PrivacyConfig


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%MZ") \
        if epoch else "—"


def render(profile: BehaviorProfile, *, privacy: Optional[PrivacyConfig] = None
           ) -> str:
    L: List[str] = []
    L.append(f"# Evidence Report — {profile.label or profile.entity_id}")
    L.append("")
    L.append("Every finding below links to the public evidence it rests on. "
             "Provenance is never discarded.")
    L.append("")

    n = 0
    for a in profile.assertions:
        L.append(f"## [{a.kind.value}] {a.statement}")
        if a.confidence:
            c = a.confidence
            L.append(f"- Confidence **{c.score:.2f}** ({c.band}); "
                     f"sample {c.sample_size}, period {c.observation_period_days:.0f}d, "
                     f"sources {c.source_count}.")
            if c.supporting_signals:
                L.append(f"- Supporting: {', '.join(c.supporting_signals)}.")
            if c.contradicting_signals:
                L.append(f"- Contradicting: {', '.join(c.contradicting_signals)}.")
        if a.evidence:
            L.append("- Evidence:")
            for e in a.evidence:
                n += 1
                L.append(f"    - `{e.provider or '?'}` "
                         f"{e.source_url or e.observation_id or '(no url)'} "
                         f"@ {_ts(e.timestamp)} "
                         f"(collected {_ts(e.collected_at)}, "
                         f"conf {e.confidence:.2f})")
        else:
            L.append("- Evidence: derived from the observation aggregate for this "
                     "window (see JSON export for the full observation set).")
        for lim in (a.confidence.limitations if a.confidence else []):
            L.append(f"- _Limitation ({lim.severity})_: {lim.text}")
        L.append("")

    L.append(f"**Total evidence references:** {n}")
    return "\n".join(L)
