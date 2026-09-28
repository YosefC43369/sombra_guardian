"""
threat_actor_intelligence.reports.markdown_report — dossier → Markdown.

Renders any dossier (actor/campaign/malware) produced by the ``*ReportBuilder``
classes into a readable Markdown investigation document. Every section preserves
the epistemic framing: confidence bands are shown, the limitations block is
always rendered last, and infrastructure/IOC values are defanged.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _dt(ts: float) -> str:
    if not ts:
        return "unknown"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return "unknown"


def _h(level: int, text: str) -> str:
    return f"{'#' * level} {text}\n"


def render(dossier: Dict[str, Any]) -> str:
    kind = dossier.get("kind", "entity")
    if kind == "actor":
        return _render_actor(dossier)
    if kind == "campaign":
        return _render_campaign(dossier)
    if kind == "malware":
        return _render_malware(dossier)
    return "# Report\n\n(unknown dossier kind)\n"


def _confidence_block(dossier: Dict[str, Any]) -> str:
    conf = dossier.get("confidence") or {}
    out = [_h(2, "Confidence")]
    if not conf:
        out.append("_No confidence computed (no evidence)._\n")
        return "\n".join(out)
    out.append(f"- **Score:** {conf.get('score_100', 0)}/100 "
               f"(**{conf.get('band', 'n/a')}**)")
    out.append(f"- **Independent sources:** "
               f"{', '.join(conf.get('supporting_signals', [])) or 'none'}")
    factors = conf.get("factors", {})
    if factors:
        out.append("- **Factors:** " + ", ".join(
            f"{k}={v}" for k, v in factors.items()))
    out.append("")
    return "\n".join(out)


def _limitations_block(dossier: Dict[str, Any]) -> str:
    lims = dossier.get("limitations", [])
    out = [_h(2, "Limitations")]
    if not lims:
        out.append("_None recorded._\n")
        return "\n".join(out)
    for l in lims:
        sev = l.get("severity", "info").upper()
        out.append(f"- _({sev})_ {l.get('text', '')}")
    out.append("")
    return "\n".join(out)


def _evidence_block(dossier: Dict[str, Any]) -> str:
    ev = dossier.get("evidence", [])
    out = [_h(2, "Evidence")]
    if not ev:
        out.append("_No evidence citations._\n")
        return "\n".join(out)
    out.append("| Provider | Class | Title | Observed | Source |")
    out.append("|---|---|---|---|---|")
    for e in ev[:60]:
        out.append(f"| {e.get('provider', '')} | {e.get('source_class', '')} | "
                   f"{(e.get('title', '') or '')[:60]} | {_dt(e.get('observed_at', 0))} "
                   f"| {(e.get('source_url', '') or '')[:60]} |")
    out.append("")
    return "\n".join(out)


def _attack_block(dossier: Dict[str, Any]) -> str:
    cov = dossier.get("attack_coverage", {})
    out = [_h(2, "ATT&CK Coverage")]
    out.append(f"- Tactics covered: {cov.get('tactics_covered', 0)}/"
               f"{cov.get('tactics_total', 14)} "
               f"(coverage score {cov.get('coverage_score', 0)})")
    out.append(f"- Techniques documented: {cov.get('techniques', 0)}\n")
    for t in cov.get("by_tactic", []):
        techs = ", ".join(t.get("techniques", []))
        out.append(f"- **{t.get('name', t.get('short_name'))}**: {techs}")
    out.append("")
    return "\n".join(out)


def _render_actor(d: Dict[str, Any]) -> str:
    ident = d.get("identity", {})
    parts = [_h(1, f"Threat Actor Dossier — {ident.get('canonical_name', '')}")]
    parts.append(f"_Generated {_dt(d.get('generated_at', 0))} · "
                 f"actor_id `{ident.get('actor_id', '')}`_\n")
    parts.append(_h(2, "Executive Summary"))
    parts.append(d.get("executive_summary", "") + "\n")

    parts.append(_h(2, "Identity"))
    parts.append(f"- **Type:** {ident.get('actor_type', '')}")
    if ident.get("attack_group_id"):
        parts.append(f"- **ATT&CK Group:** {ident['attack_group_id']}")
    parts.append(f"- **First / last observed:** {_dt(ident.get('first_seen', 0))} → "
                 f"{_dt(ident.get('last_seen', 0))}")
    if ident.get("suspected_origin"):
        parts.append(f"- **Suspected origin (reported):** {ident['suspected_origin']}")
    if ident.get("motivations"):
        parts.append(f"- **Motivations:** {', '.join(ident['motivations'])}")
    parts.append("")

    aliases = d.get("aliases", [])
    parts.append(_h(2, "Aliases"))
    if aliases:
        for a in aliases:
            parts.append(f"- **{a.get('name', '')}** "
                         f"(_{a.get('kind', '')}_, source: {a.get('source', 'n/a')})")
    else:
        parts.append("_No tracked aliases._")
    parts.append("")

    parts.append(_h(2, "Campaign Timeline"))
    tl = d.get("campaign_timeline", {})
    parts.append(f"_Span {tl.get('period_start_iso', '')} → "
                 f"{tl.get('period_end_iso', '')} "
                 f"({tl.get('event_count', 0)} events)_\n")
    for ev in tl.get("events", [])[:40]:
        parts.append(f"- `{ev.get('iso', '')}` **{ev.get('kind', '')}** — "
                     f"{ev.get('label', '')}")
    parts.append("")

    parts.append(_h(2, "Malware Relationships"))
    for m in d.get("malware_relationships", []):
        parts.append(f"- **{m.get('name', '')}** ({m.get('category', 'n/a')}) — "
                     f"{len(m.get('techniques', []))} technique(s), "
                     f"{m.get('hashes_known', 0)} sample ref(s)")
    parts.append("")

    parts.append(_attack_block(d))

    parts.append(_h(2, "Infrastructure Relationships"))
    for n in d.get("infrastructure", []):
        parts.append(f"- `{n.get('value', '')}` ({n.get('type', '')}) "
                     f"ASN {n.get('asn', 'n/a')} {n.get('country', '')} "
                     f"{('· ' + n['role']) if n.get('role') else ''}")
    parts.append("")

    parts.append(_h(2, "Victimology"))
    vic = d.get("victimology", {})
    if vic.get("countries"):
        parts.append(f"- **Countries:** " + ", ".join(
            f"{k} ({v})" for k, v in vic["countries"].items()))
    if vic.get("sectors"):
        parts.append(f"- **Sectors:** " + ", ".join(
            f"{k} ({v})" for k, v in vic["sectors"].items()))
    if not vic.get("countries") and not vic.get("sectors"):
        parts.append("_No documented victimology._")
    parts.append("")

    parts.append(_h(2, "Public Reports"))
    for r in d.get("public_reports", [])[:40]:
        parts.append(f"- [{r.get('title', r.get('report_id', ''))}]"
                     f"({r.get('url', '')}) — {r.get('source', '')} "
                     f"{_dt(r.get('published_at', 0))}")
    parts.append("")

    parts.append(_attack_or_evidence(d))
    return "\n".join(parts)


def _attack_or_evidence(d: Dict[str, Any]) -> str:
    return _evidence_block(d) + "\n" + _confidence_block(d) + "\n" + _limitations_block(d)


def _render_campaign(d: Dict[str, Any]) -> str:
    ident = d.get("identity", {})
    parts = [_h(1, f"Campaign Dossier — {ident.get('campaign_name', '')}")]
    parts.append(f"_Generated {_dt(d.get('generated_at', 0))} · "
                 f"campaign_id `{ident.get('campaign_id', '')}`_\n")
    parts.append(_h(2, "Executive Summary"))
    parts.append(d.get("executive_summary", "") + "\n")
    parts.append(_h(2, "Overview"))
    parts.append(f"- **Duration:** {ident.get('duration_days', 0)} days "
                 f"({_dt(ident.get('first_observed', 0))} → "
                 f"{_dt(ident.get('last_observed', 0))})")
    if ident.get("summary"):
        parts.append(f"- {ident['summary'][:400]}")
    parts.append("")
    parts.append(_h(2, "Attributed Actors"))
    for a in d.get("attributed_actors", []):
        parts.append(f"- **{a.get('name', '')}** ({a.get('type', '')})")
    if not d.get("attributed_actors"):
        parts.append("_No confidently attributed actor._")
    parts.append("")
    parts.append(_h(2, "Malware Relationships"))
    for m in d.get("malware_relationships", []):
        parts.append(f"- **{m.get('name', '')}** ({m.get('category', 'n/a')})")
    parts.append("")
    parts.append(_attack_block(d))
    parts.append(_h(2, "Infrastructure Relationships"))
    for n in d.get("infrastructure", []):
        parts.append(f"- `{n.get('value', '')}` ({n.get('type', '')}) "
                     f"ASN {n.get('asn', 'n/a')} {n.get('country', '')}")
    parts.append("")
    parts.append(_h(2, "Indicators of Compromise"))
    for i in d.get("iocs", [])[:80]:
        parts.append(f"- `{i.get('defanged', i.get('value', ''))}` "
                     f"({i.get('type', '')})")
    parts.append("")
    parts.append(_h(2, "Victimology"))
    vic = d.get("victimology", {})
    if vic.get("countries"):
        parts.append("- **Countries:** " + ", ".join(
            f"{k} ({v})" for k, v in vic["countries"].items()))
    if vic.get("sectors"):
        parts.append("- **Sectors:** " + ", ".join(
            f"{k} ({v})" for k, v in vic["sectors"].items()))
    parts.append("")
    parts.append(_attack_or_evidence(d))
    return "\n".join(parts)


def _render_malware(d: Dict[str, Any]) -> str:
    ident = d.get("identity", {})
    parts = [_h(1, f"Malware Family Dossier — {ident.get('name', '')}")]
    parts.append(f"_Generated {_dt(d.get('generated_at', 0))} · "
                 f"family_id `{ident.get('family_id', '')}`_\n")
    parts.append(_h(2, "Executive Summary"))
    parts.append(d.get("executive_summary", "") + "\n")
    parts.append(_h(2, "Identity"))
    parts.append(f"- **Category:** {ident.get('category', 'n/a')}")
    parts.append(f"- **Platforms:** {', '.join(ident.get('platforms', [])) or 'n/a'}")
    parts.append(f"- **Languages:** {', '.join(ident.get('languages', [])) or 'n/a'}")
    if ident.get("attack_software_id"):
        parts.append(f"- **ATT&CK Software:** {ident['attack_software_id']}")
    parts.append("")
    parts.append(_h(2, "Aliases"))
    for a in d.get("aliases", []):
        parts.append(f"- **{a.get('name', '')}** (source: {a.get('source', 'n/a')})")
    if not d.get("aliases"):
        parts.append("_No tracked aliases._")
    parts.append("")
    parts.append(_h(2, "Associated Actors & Campaigns"))
    for a in d.get("actors", []):
        parts.append(f"- Actor: **{a.get('name', '')}**")
    for c in d.get("campaigns", []):
        parts.append(f"- Campaign: **{c.get('name', '')}**")
    parts.append("")
    parts.append(_attack_block(d))
    kh = d.get("known_hashes", {})
    parts.append(_h(2, "Known Public Sample References"))
    parts.append(f"_{kh.get('count', 0)} referenced hash(es). {kh.get('note', '')}_")
    for h in kh.get("samples", [])[:20]:
        parts.append(f"- `{h}`")
    parts.append("")
    parts.append(_attack_or_evidence(d))
    return "\n".join(parts)


__all__ = ["render"]
