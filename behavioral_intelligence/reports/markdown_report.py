"""
behavioral_intelligence.reports.markdown_report — the primary human-readable
report (spec §50, §51).

Renders a ``BehaviorProfile`` as Markdown with the mandated section structure and
the epistemic labelling that is the point of this engine: every analytical line
is prefixed with its ``AssertionKind`` (OBSERVED / CORRELATED / INFERRED /
UNKNOWN) so a reader can never mistake a correlation for a conclusion. Confidence,
observation period, evidence count and limitations travel with the findings.

Privacy (spec §34): account ids are masked and sample text truncated according to
the supplied ``PrivacyConfig``; no raw personal text is emitted beyond the
configured budget.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List, Optional

from ..models.behavior import BehaviorProfile
from ..models.confidence import Assertion, AssertionKind
from ..configuration import PrivacyConfig


def _ts(epoch: float) -> str:
    if not epoch:
        return "—"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%MZ")


def _date(epoch: float) -> str:
    if not epoch:
        return "—"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def _mask(account: str, privacy: PrivacyConfig) -> str:
    if not privacy.mask_account_ids or not account:
        return account
    h = hashlib.sha256(account.encode()).hexdigest()[:8]
    return f"acct:{h}"


def _assertions_block(assertions: List[Assertion], kinds: Optional[set] = None
                      ) -> List[str]:
    lines: List[str] = []
    for a in assertions:
        if kinds and a.kind not in kinds:
            continue
        conf = f" _(confidence {a.score:.2f})_" if a.confidence else ""
        lines.append(f"- **[{a.kind.value}]** {a.statement}{conf}")
    return lines


def render(profile: BehaviorProfile, *, privacy: Optional[PrivacyConfig] = None
           ) -> str:
    privacy = privacy or PrivacyConfig()
    p = profile
    L: List[str] = []

    L.append("# Behavioral Intelligence Report")
    L.append("")
    L.append(f"**Entity:** {p.label or p.entity_id or '(unnamed)'}  ")
    L.append(f"**Observation period:** {_date(p.period_start)} → {_date(p.period_end)}  ")
    L.append(f"**Public observations:** {p.sample_size:,}  ")
    L.append(f"**Platforms:** {len(p.platforms)} ({', '.join(p.platforms) or '—'})  ")
    L.append(f"**Generated:** {_ts(p.generated_at)}")
    L.append("")
    L.append("> This report describes **observable public activity patterns**. It "
             "makes no claim about the person behind the account — no "
             "psychological, medical, criminal-intent, ideological or identity "
             "conclusion is implied or supported.")
    L.append("")

    # legend
    L.append("**Epistemic labels:** `OBSERVED` = directly in the data · "
             "`CORRELATED` = facts co-occur, no cause claimed · "
             "`INFERRED` = interpretation of observed facts · "
             "`UNKNOWN` = data cannot establish it.")
    L.append("")

    # 1. Executive summary
    L.append("## 1. Executive Summary")
    L.append("")
    observed = _assertions_block(p.assertions, {AssertionKind.OBSERVED})
    if observed:
        L.extend(observed[:6])
    else:
        L.append("- No observations available for this window.")
    L.append("")

    # 2. Observed activity
    L.append("## 2. Observed Activity")
    if p.activity:
        a = p.activity
        L.append(f"- Posting rate: **{a.posts_per_day:.2f}/day** over "
                 f"{a.period_days:.0f} days ({a.active_days} active / "
                 f"{a.inactive_days} inactive days; coverage {a.coverage*100:.0f}%).")
        L.append(f"- Median inter-post interval: "
                 f"{a.intervals.median/3600:.1f} h "
                 f"(min {a.intervals.minimum/3600:.1f}h, "
                 f"max {a.intervals.maximum/3600:.1f}h).")
        if a.per_platform:
            L.append("- Per platform: " +
                     ", ".join(f"{k} {v}" for k, v in sorted(
                         a.per_platform.items(), key=lambda kv: -kv[1])))
    L.append("")

    # 3. Temporal analysis
    L.append("## 3. Temporal Analysis")
    if p.peak_windows:
        w = p.peak_windows[0]
        L.append(f"- **[OBSERVED]** Peak activity window: **{w.label()}** "
                 f"({w.share*100:.0f}% of timed activity). Stated in UTC; timezone "
                 f"is not asserted as identity evidence.")
    for b in p.bursts[:3]:
        L.append(f"- **[OBSERVED]** Burst: {b.count} items in "
                 f"{b.duration_seconds/60:.0f} min ({b.relative_change:.1f}× baseline).")
    for g in p.inactivity[:3]:
        L.append(f"- **[OBSERVED]** Inactivity gap: {g.duration_days:.0f} days with "
                 f"no observed public activity (lack of observation, not absence).")
    if not (p.peak_windows or p.bursts or p.inactivity):
        L.append("- No notable temporal structure in this window.")
    L.append("")

    # 4. Language analysis
    L.append("## 4. Language Analysis")
    if p.languages and p.languages.shares:
        top = sorted(p.languages.shares.items(), key=lambda kv: kv[1], reverse=True)
        L.append("- **[OBSERVED]** Public language use: " +
                 ", ".join(f"{lang} {share*100:.0f}%" for lang, share in top[:5]) + ".")
        L.append("- _Language use is observed; nationality/ethnicity are NOT inferred._")
    else:
        L.append("- No language-bearing text observed.")
    L.append("")

    # 5. Topic evolution
    L.append("## 5. Topic Evolution")
    if p.keywords:
        L.append("- **[OBSERVED]** Top terms: " +
                 ", ".join(f"`{k.term}`" for k in p.keywords[:10]) + ".")
    if p.topic_evolution and (p.topic_evolution.emerged or p.topic_evolution.faded):
        if p.topic_evolution.emerged:
            L.append("- **[OBSERVED]** Emerged recently: " +
                     ", ".join(f"`{t}`" for t in p.topic_evolution.emerged[:8]))
        if p.topic_evolution.faded:
            L.append("- **[OBSERVED]** Faded: " +
                     ", ".join(f"`{t}`" for t in p.topic_evolution.faded[:8]))
    if p.hashtags:
        L.append("- **[OBSERVED]** Hashtags: " +
                 ", ".join(f"#{h.tag}({h.frequency})" for h in p.hashtags[:8]) + ".")
    L.append("")

    # 6. Interaction network
    L.append("## 6. Public Interaction Network")
    if p.interactions and p.interactions.edges:
        net = p.interactions
        L.append(f"- **[OBSERVED]** {len(net.edges)} directed interaction edges; "
                 f"reciprocity {net.reciprocity:.2f}.")
        for e in net.edges[:5]:
            L.append(f"    - {_mask(e.source, privacy)} → "
                     f"{_mask(e.target, privacy)} ×{e.count}")
        L.append("- _Interactions are observed public acts; no private "
                 "relationship is inferred._")
    else:
        L.append("- No public interactions observed.")
    L.append("")

    # 7. Domain / infrastructure activity
    L.append("## 7. Domain Activity")
    if p.domains:
        for d in p.domains[:8]:
            flag = " (shortener)" if d.is_shortener else ""
            L.append(f"- **[OBSERVED]** `{d.domain}` ×{d.frequency}{flag}")
    else:
        L.append("- No domains referenced.")
    L.append("")

    # 8. Anomalies
    L.append("## 8. Anomalies (relative to observed baseline)")
    if p.anomaly_score:
        L.append(f"- Anomaly score: **{p.anomaly_score.score:.0f}/100** "
                 f"({p.anomaly_score.band}). _This is a deviation measure, NOT a "
                 f"threat/criminality score._")
        for dev in p.anomaly_score.top_features(5):
            L.append(f"    - {dev.feature}: {dev.note} (+{dev.contribution:.0f})")
    for an in p.anomalies[:5]:
        L.append(f"- **[OBSERVED]** [{an.severity}] {an.description}")
    L.append("")

    # 9. Change points
    L.append("## 9. Change Points")
    if p.change_points:
        for c in p.change_points[:6]:
            L.append(f"- **[OBSERVED]** {_ts(c.at)}: {c.detail} "
                     f"(method={c.method}, {c.magnitude:.1f}σ)")
    else:
        L.append("- No statistical change points detected.")
    L.append("")

    # 10. Correlated / inferred findings, kept explicitly separate
    corr = _assertions_block(p.assertions, {AssertionKind.CORRELATED,
                                            AssertionKind.INFERRED})
    L.append("## 10. Correlated & Inferred Findings")
    if corr:
        L.extend(corr)
        L.append("")
        L.append("> CORRELATED/INFERRED items are leads for analyst review, not "
                 "established facts.")
    else:
        L.append("- None.")
    L.append("")

    # 11. Evidence & confidence
    L.append("## 11. Evidence & Confidence")
    scored = [a for a in p.assertions if a.confidence]
    if scored:
        mean_conf = sum(a.score for a in scored) / len(scored)
        L.append(f"- Findings: {len(p.assertions)} "
                 f"({len(observed)} observed). Mean confidence "
                 f"{mean_conf:.2f}.")
        srcs = {e.provider for a in scored for e in a.evidence if e.provider}
        if srcs:
            L.append(f"- Independent sources referenced: {len(srcs)} "
                     f"({', '.join(sorted(srcs))}).")
    if p.provider_status:
        ok = sum(1 for s in p.provider_status if s.get("status") == "ok")
        L.append(f"- Providers: {ok}/{len(p.provider_status)} returned data.")
    L.append("")

    # 12. Limitations
    L.append("## 12. Limitations")
    for lim in p.limitations:
        L.append(f"- {lim}")
    L.append("")
    L.append("---")
    L.append("_Machine-generated for authorized investigation. Treat findings as "
             "leads requiring analyst review, not proven facts about any person._")
    return "\n".join(L)
