"""
web_footprint.reports.red_team — the primary passive-reconnaissance report.

Renders a :class:`ReconResult` to the 22-section Markdown structure the spec
mandates (§55), optimised for an authorized red-team researcher: what publicly
observable infrastructure, sites, documents, technologies, domains, repositories,
historical assets and relationships were mapped — each evidence-backed,
source-attributed and confidence-aware — and, crucially, a Limitations section
that states plainly what passive recon could not and did not do.

Pure string building, no dependencies.
"""

from __future__ import annotations

from typing import Any, Dict, List, TYPE_CHECKING

from ..assets import AssetType
from ..analysis import exposure as exposure_mod

if TYPE_CHECKING:
    from ..pipeline import ReconResult


def _table(headers: List[str], rows: List[List[str]], empty: str = "_None observed._") -> List[str]:
    if not rows:
        return [empty, ""]
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    out.append("")
    return out


def render(result: "ReconResult") -> str:
    inv = result.inventory
    stats = result.stats()
    L: List[str] = []

    # 1. Target
    L += [f"# Web Footprint — Passive Reconnaissance Report", "",
          f"## 1. Target", "",
          f"- Seed: `{result.target}`",
          f"- Registrable domain: `{result.base_domain}`",
          f"- Mode: **{result.config.mode.value}**",
          f"- Authorized: **{result.gate.allowed}** ({result.gate.reason})", ""]

    if not result.gate.allowed:
        L += ["> Recon was **not authorized** for this target, so no collection ran.",
              f"> Gate detail: {result.gate.detail}", "",
              "_This report is intentionally empty below the gate._"]
        return "\n".join(L)

    # 2. Scope
    by_scope = inv.counts_by_scope()
    L += ["## 2. Scope", "",
          "Assets are tagged against the declared engagement scope "
          "(IN_SCOPE / OUT_OF_SCOPE / UNKNOWN). A bug-bounty or scope declaration "
          "does not by itself grant authorization.", ""]
    L += _table(["Placement", "Assets"],
                [[k, v] for k, v in sorted(by_scope.items())])

    # 3. Executive Summary
    surf = result.observed_surface
    L += ["## 3. Executive Summary", "",
          f"- Collectors run: {stats['collectors_run']} "
          f"({stats.get('collectors_by_status', {})})",
          f"- Requests made: {stats['requests_made']} "
          f"(budget {result.config.limits.max_requests})",
          f"- Total assets: **{surf.get('total_assets', 0)}** — "
          f"{surf.get('domains',0)} domains, {surf.get('subdomains',0)} subdomains, "
          f"{surf.get('websites',0)} websites, {surf.get('documents',0)} documents, "
          f"{surf.get('repositories',0)} repositories, "
          f"{surf.get('technologies',0)} technologies",
          f"- Graph: {stats['graph_nodes']} nodes / {stats['graph_edges']} edges",
          f"- Elapsed: {result.elapsed_ms} ms",
          "",
          "_Observed public surface is reported as factual metrics; the engine "
          "does not assign a security-maturity grade (spec §46)._", ""]

    # 4. Domain Inventory
    L += ["## 4. Domain Inventory", ""]
    L += _table(["Domain", "Class", "Scope", "Confidence", "Sources"],
                [[a.value, a.domain_class.value if a.domain_class else "-",
                  a.scope.value, a.confidence_band, ", ".join(a.sources)]
                 for a in sorted(inv.of_type(AssetType.DOMAIN), key=lambda x: x.value)])

    # 5. Subdomain Inventory
    L += ["## 5. Subdomain Inventory", ""]
    subs = sorted(inv.of_type(AssetType.SUBDOMAIN), key=lambda x: x.value)
    L += _table(["Subdomain", "Role (naming signal)", "State", "Scope", "Sources"],
                [[a.value, a.subdomain_role or "-", a.signal_state.value,
                  a.scope.value, ", ".join(a.sources)] for a in subs])
    if any(a.subdomain_role and a.subdomain_role in
           ("admin", "auth", "vpn", "staging", "development") for a in subs):
        L += ["_Role labels are naming signals only — a name like `admin` does "
              "not imply an exposed admin interface (spec §6)._", ""]

    # 6. Website Inventory
    L += ["## 6. Website Inventory", ""]
    L += _table(["URL", "Title", "State", "Scope"],
                [[a.url or a.value, (a.label or a.attributes.get("title", ""))[:60],
                  a.signal_state.value, a.scope.value]
                 for a in sorted(inv.of_type(AssetType.WEBSITE), key=lambda x: x.value)])

    # 7. Public API / Documentation
    L += ["## 7. Public API / Documentation", ""]
    L += _table(["Reference", "Kind", "Classification"],
                [[a.value, a.attributes.get("kind", ""),
                  a.attributes.get("classification", "")]
                 for a in sorted(inv.of_type(AssetType.API, AssetType.DOCUMENTATION),
                                 key=lambda x: x.value)])

    # 8. Technology Footprint
    L += ["## 8. Technology Footprint", ""]
    tech_rows: List[List[str]] = []
    seen_tech = set()
    for a in inv:
        for t in a.technologies:
            name = str(t.get("name", ""))
            key = (name.lower(), t.get("version", ""))
            if not name or key in seen_tech:
                continue
            seen_tech.add(key)
            tech_rows.append([name, t.get("category", ""), t.get("version", "") or "-",
                              t.get("source", "")])
    L += _table(["Technology", "Category", "Version", "Source"],
                sorted(tech_rows, key=lambda r: (r[1], r[0].lower())))
    L += ["_A version is an observation, not a vulnerability claim (spec §9)._", ""]

    # 9. DNS Intelligence
    L += ["## 9. DNS Intelligence", ""]
    L += _table(["Host", "RR", "Value", "Sources"],
                [[a.attributes.get("host", ""), a.attributes.get("rr_type", ""),
                  a.attributes.get("data", ""), ", ".join(a.sources)]
                 for a in sorted(inv.of_type(AssetType.DNS_RECORD), key=lambda x: x.value)])

    # 10. Certificate Intelligence
    L += ["## 10. Certificate Intelligence", ""]
    L += _table(["Issuer", "Not before", "Not after", "SAN count"],
                [[a.attributes.get("issuer", "")[:50], a.attributes.get("not_before", ""),
                  a.attributes.get("not_after", ""), len(a.attributes.get("sans", []) or [])]
                 for a in sorted(inv.of_type(AssetType.CERTIFICATE), key=lambda x: x.value)])

    # 11. Hosting / Infrastructure
    L += ["## 11. Hosting / Infrastructure", ""]
    L += _table(["IP", "Host", "Sources"],
                [[a.value, a.attributes.get("host", ""), ", ".join(a.sources)]
                 for a in sorted(inv.of_type(AssetType.IP), key=lambda x: x.value)])

    # 12. Public Documents
    L += ["## 12. Public Documents", ""]
    L += _table(["URL", "Type", "Timestamp"],
                [[a.url or a.value, a.attributes.get("ext", ""),
                  a.attributes.get("timestamp", "")]
                 for a in sorted(inv.of_type(AssetType.PUBLIC_FILE, AssetType.DOCUMENTATION),
                                 key=lambda x: x.value)])

    # 13. Public Repositories
    L += ["## 13. Public Repositories", ""]
    L += _table(["Repository", "Stars", "Language", "Relevant"],
                [[a.value, a.attributes.get("stars", 0), a.attributes.get("language", ""),
                  a.attributes.get("relevant", False)]
                 for a in sorted(inv.of_type(AssetType.REPOSITORY),
                                 key=lambda x: -int(x.attributes.get("stars", 0) or 0))])

    # 14. Developer Footprint
    L += ["## 14. Developer Footprint", ""]
    pkg = [s for s in result.extra_signals if s.get("type") == "package_reference"]
    pipe = [s for s in result.extra_signals if s.get("type") == "pipeline_reference"]
    emails = sorted(a.value for a in inv.of_type(AssetType.EMAIL))
    L += [f"- Public emails: {', '.join(f'`{e}`' for e in emails) if emails else '_none_'}",
          f"- Package references: "
          f"{', '.join(sorted({p.get('ecosystem','')+':'+p.get('value','') for p in pkg})) or '_none_'}",
          f"- CI/CD & container references: "
          f"{', '.join(sorted({p.get('value','') for p in pipe})) or '_none_'}", ""]

    # 15. Historical Footprint
    L += ["## 15. Historical Footprint", ""]
    hist_assets = [a for a in inv if a.signal_state.value in ("historical", "archived")]
    L += [f"- Historical/archived assets: **{len(hist_assets)}**"]
    if result.technology_timeline:
        L += ["", "Technology timeline (first→last observed):", ""]
        L += _table(["Technology", "First seen", "Last seen", "Versions"],
                    [[t["technology"], t["first_seen"], t["last_seen"],
                      ", ".join(t["versions"]) or "-"] for t in result.technology_timeline])
    else:
        L += ["_No technology timeline in this mode._", ""]
    L += ["_A removed asset means 'no longer observed', not confirmed deleted "
          "(spec §29)._", ""]

    # 16. Public Cloud Signals
    L += ["## 16. Public Cloud Signals", ""]
    L += _table(["Reference", "Provider", "Classification"],
                [[a.value, a.attributes.get("provider", ""),
                  a.attributes.get("classification", "PUBLIC_REFERENCE")]
                 for a in sorted(inv.of_type(AssetType.CLOUD_REFERENCE), key=lambda x: x.value)])
    L += ["_References only; access controls were not tested (spec §12, §13)._", ""]

    # 17. Attack-Surface Graph
    g = result.graph
    L += ["## 17. Attack-Surface Graph", "",
          f"- Nodes: {g.node_count}  |  Edges: {g.edge_count}",
          "- Edge kinds are passive, observed relationships only "
          "(no exploitation edges).", ""]
    edge_counts: Dict[str, int] = {}
    for e in g.edges():
        edge_counts[e.kind] = edge_counts.get(e.kind, 0) + 1
    L += _table(["Edge kind", "Count"], [[k, v] for k, v in sorted(edge_counts.items())],
                empty="_Graph not built in this mode._")

    # 18. Passive Exposure Signals
    L += ["## 18. Passive Exposure Signals", ""]
    exp_summary = exposure_mod.summarize_exposure(result.exposure_signals)
    L += _table(["Category", "Signals"],
                [[k, v] for k, v in sorted(exp_summary.items())])
    secrets = [s for s in result.extra_signals if s.get("type") == "secret_signal"]
    internals = [s for s in result.extra_signals if s.get("type") == "internal_naming_signal"]
    if secrets:
        L += [f"- Redacted secret-like strings: **{len(secrets)}** "
              f"(classified, NOT validated or used — spec §24)", ""]
    if internals:
        L += [f"- Internal-naming signals: **{len(internals)}** "
              f"(reconnaissance information only — spec §22)", ""]

    # 19. Correlations
    L += ["## 19. Correlations", ""]
    corr_rows: List[List[str]] = []
    for a in sorted(inv.assets(), key=lambda x: -len(x.sources))[:15]:
        if len(a.sources) > 1:
            corr_rows.append([a.value, a.asset_type.value, ", ".join(a.sources)])
    L += _table(["Asset", "Type", "Corroborating sources"], corr_rows,
                empty="_No multi-source corroboration yet (single-source run)._")

    # 20. Evidence
    L += ["## 20. Evidence", "",
          "Every asset carries append-only evidence (source + timestamp). Top "
          "assets by relevance:", ""]
    top = result.relevance.get("assets", [])[:10]
    L += _table(["Asset", "Type", "Relevance", "Band"],
                [[a["asset"], a["type"], a["relevance"]["score"], a["relevance"]["band"]]
                 for a in top])

    # 21. Confidence
    L += ["## 21. Confidence", "",
          f"- Average passive-recon relevance: "
          f"**{result.relevance.get('average_relevance', 0)}** / 100",
          f"- Max relevance: {result.relevance.get('max_relevance', 0)} / 100",
          "- Relevance is corroboration- and source-quality-based; it is **not** "
          "a vulnerability score (spec §45).", ""]

    # 22. Limitations
    L += ["## 22. Limitations", "",
          "- **Passive only.** No active scanning, exploitation, credential "
          "access, authentication bypass, stealth/evasion, or CAPTCHA/rate-limit "
          "bypass was performed. The engine stops at reconnaissance (spec §60).",
          "- **Public sources only.** Findings reflect what public sources "
          "(certificate transparency, public DNS, the Wayback archive, the "
          "target's own published files, public repositories) exposed at query "
          "time; absence of a finding is not proof of absence.",
          "- **Discovery ≠ ownership.** A discovered asset is not asserted to "
          "belong to the target unless the evidence supports it; shared hosting, "
          "nameservers or certificates are signals, not proof of ownership "
          "(spec §16, §43).",
          "- **Naming ≠ exposure.** Role labels and internal-naming signals are "
          "hints from names, not claims that a service is reachable or exposed.",
          "- **Version ≠ vulnerability.** Observed versions are recorded as "
          "facts; no vulnerability was inferred or tested (spec §9).",
          "- **Budgeted.** The run honoured its request budget, runtime cap and "
          "pivot-depth ceiling; a larger run may observe more.", ""]

    return "\n".join(L).rstrip() + "\n"
