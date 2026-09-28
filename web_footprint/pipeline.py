"""
web_footprint.pipeline — the passive reconnaissance pipeline (spec §2).

This is the backbone that turns a seed target into an evidence-backed
attack-surface picture, in the order the spec lays out:

    seed → AUTHORIZE (fail-closed gate) → run enabled COLLECTORS (passive,
    concurrent, budget-bounded) → INGEST records into the inventory → run the
    offline ANALYZERS (subdomain roles, technology, reference extraction,
    security signals) → CLASSIFY SCOPE → build the ATTACK-SURFACE GRAPH →
    EXPOSURE analysis → RELEVANCE scoring → (DEEP) depth-bounded passive PIVOTS.

Everything the pipeline does is passive. It never authorizes itself — the seed
is checked against :class:`web_footprint.authorization.ReconGate` before any
collector runs, and discovered assets are tagged IN/OUT/UNKNOWN against the
declared scope. Every ceiling in :class:`ReconLimits` is honoured: collector
concurrency, the total request budget, the wall-clock cap and the per-type asset
caps, plus the pivot-depth ceiling. Collectors are injectable, so the whole
pipeline is unit-tested offline with canned collector results.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .assets import (Asset, AssetType, AttackSurfaceInventory, Evidence,
                     SignalState, DomainClass, ScopeStatus)
from .authorization import ReconContext, ReconGate, GateDecision
from .config import ReconConfig, ReconMode, ReconLimits
from .collectors.base import Collector, CollectorResult, CollectorStatus
from . import graph as graphmod
from . import normalize, scoring, history
from .analysis import subdomain_roles, tech, extract, security_signals, exposure

logger = logging.getLogger("modbot.web_footprint.pipeline")

try:
    from osint.utils.async_http import AsyncHTTPClient, HAVE_HTTPX
except Exception:  # pragma: no cover
    AsyncHTTPClient = None
    HAVE_HTTPX = False


@dataclass
class ReconResult:
    """The full output of one recon run."""

    target: str
    base_domain: str
    config: ReconConfig
    gate: GateDecision
    inventory: AttackSurfaceInventory
    graph: graphmod.AttackSurfaceGraph
    collector_results: List[CollectorResult] = field(default_factory=list)
    exposure_signals: List[Any] = field(default_factory=list)
    observed_surface: Dict[str, Any] = field(default_factory=dict)
    relevance: Dict[str, Any] = field(default_factory=dict)
    extra_signals: List[Dict[str, Any]] = field(default_factory=list)
    security: List[Dict[str, Any]] = field(default_factory=list)
    technology_timeline: List[Dict[str, Any]] = field(default_factory=list)
    requests_made: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def elapsed_ms(self) -> int:
        return int((self.finished_at - self.started_at) * 1000)

    def stats(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        for r in self.collector_results:
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        return {
            "target": self.target,
            "base_domain": self.base_domain,
            "mode": self.config.mode.value,
            "authorized": self.gate.allowed,
            "collectors_run": len(self.collector_results),
            "collectors_by_status": by_status,
            "requests_made": self.requests_made,
            "assets": len(self.inventory),
            "assets_by_type": self.inventory.counts_by_type(),
            "assets_by_scope": self.inventory.counts_by_scope(),
            "graph_nodes": self.graph.node_count,
            "graph_edges": self.graph.edge_count,
            "elapsed_ms": self.elapsed_ms,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats(),
            "gate": self.gate.to_dict(),
            "config": self.config.to_dict(),
            "observed_surface": self.observed_surface,
            "relevance": self.relevance,
            "exposure": [s.to_dict() for s in self.exposure_signals],
            "exposure_summary": exposure.summarize_exposure(self.exposure_signals),
            "security_signals": self.security,
            "technology_timeline": self.technology_timeline,
            "extra_signals": self.extra_signals,
            "inventory": self.inventory.to_dict(),
            "graph": self.graph.to_dict(),
            "collectors": [r.to_dict() for r in self.collector_results],
        }


class ReconPipeline:
    def __init__(self, collectors: Optional[List[Collector]] = None, *,
                 gate: Optional[ReconGate] = None) -> None:
        if collectors is None:
            from .collectors import default_collectors
            collectors = default_collectors()
        self.collectors = list(collectors)
        self.gate = gate or ReconGate()

    # -- public entry ------------------------------------------------------ #

    async def run(self, target: str, ctx: ReconContext, *,
                  config: Optional[ReconConfig] = None,
                  client: Optional[Any] = None) -> ReconResult:
        config = config or ReconConfig()
        base = normalize.registrable_domain(target) or (
            normalize.normalize_domain(target) or str(target).lower())
        inventory = AttackSurfaceInventory(target=base)
        graph = graphmod.AttackSurfaceGraph(target=base)
        result = ReconResult(target=str(target), base_domain=base, config=config,
                             gate=GateDecision(False, "", ""), inventory=inventory,
                             graph=graph, started_at=time.monotonic())

        # 1) AUTHORIZE the seed. Fail-closed: no collector runs on a denial.
        decision = self.gate.authorize_seed(ctx, target)
        result.gate = decision
        if not decision.allowed:
            result.finished_at = time.monotonic()
            logger.warning("web_footprint recon denied for %r: %s",
                           target, decision.reason)
            return result

        # 2) run collectors (+ optional passive pivots), ingesting as we go.
        owns_client = False
        if client is None and HAVE_HTTPX and AsyncHTTPClient is not None:
            client = AsyncHTTPClient(rate=config.limits.rate_per_host)
            await client.__aenter__()
            owns_client = True
        try:
            await self._collect_and_ingest(result, ctx, base, client)
        finally:
            if owns_client:
                await client.__aexit__(None, None, None)

        # 3) offline analysis, scope, graph, exposure, scoring.
        self._finalize(result, ctx, base)
        result.finished_at = time.monotonic()
        return result

    # -- collection -------------------------------------------------------- #

    def _enabled_collectors(self, config: ReconConfig) -> List[Collector]:
        return [c for c in self.collectors
                if not c.stage or config.enabled(c.stage)]

    async def _run_collectors(self, targets: List[str], result: ReconResult,
                              client: Any) -> List[CollectorResult]:
        cfg = result.config
        selected = self._enabled_collectors(cfg)
        sem = asyncio.Semaphore(max(1, cfg.limits.concurrency))
        budget_left = max(0, cfg.limits.max_requests - result.requests_made)
        deadline = result.started_at + cfg.limits.max_runtime_s

        async def _one(collector: Collector, tgt: str) -> Optional[CollectorResult]:
            if result.requests_made >= cfg.limits.max_requests:
                return None
            if time.monotonic() > deadline:
                return None
            async with sem:
                res = await collector.run(client, tgt, cfg.limits)
                result.requests_made += res.requests_made
                return res

        tasks = [ _one(c, t) for t in targets for c in selected ]
        gathered = await asyncio.gather(*tasks) if tasks else []
        return [r for r in gathered if r is not None]

    async def _collect_and_ingest(self, result: ReconResult, ctx: ReconContext,
                                  base: str, client: Any) -> None:
        cfg = result.config
        # depth 0: the seed's registrable domain.
        seen_domains = {base}
        pending = [base]
        max_depth = cfg.limits.max_pivot_depth if cfg.enabled("pivots") else 0

        for depth in range(max_depth + 1):
            if not pending:
                break
            results = await self._run_collectors(pending, result, client)
            result.collector_results.extend(results)
            for r in results:
                self._ingest(r, result, base)

            if depth >= max_depth:
                break
            # Discover pivot targets: newly-seen registrable domains that are
            # in the declared scope (or, with no scope declared, share the seed
            # base). Never pivot into a domain the scope marks out.
            classifier = ctx.classifier()
            nxt: List[str] = []
            for asset in result.inventory:
                host = asset.subdomain or (asset.value if asset.asset_type in (
                    AssetType.DOMAIN, AssetType.SUBDOMAIN) else "")
                reg = normalize.registrable_domain(host) if host else None
                if not reg or reg in seen_domains:
                    continue
                status = classifier.scope.classify_host(reg)
                same_base = reg == base
                if status is ScopeStatus.OUT_OF_SCOPE:
                    continue
                if status is ScopeStatus.IN_SCOPE or same_base:
                    if len(seen_domains) >= cfg.limits.max_domains:
                        break
                    seen_domains.add(reg)
                    nxt.append(reg)
            pending = nxt

    # -- ingestion --------------------------------------------------------- #

    def _cap_reached(self, inventory: AttackSurfaceInventory, atype: AssetType,
                     limit: int) -> bool:
        return len(inventory.of_type(atype)) >= max(1, limit)

    def _ingest(self, cres: CollectorResult, result: ReconResult, base: str) -> None:
        inv = result.inventory
        lim = result.config.limits
        for rec in cres.records:
            rtype = rec.get("type")
            src = rec.get("source", cres.collector)
            try:
                self._ingest_record(rtype, rec, src, inv, base, lim, result)
            except Exception:  # one bad record never breaks a run
                logger.debug("ingest failed for record %r", rtype, exc_info=True)

    def _ingest_record(self, rtype: str, rec: Dict[str, Any], src: str,
                       inv: AttackSurfaceInventory, base: str, lim: ReconLimits,
                       result: ReconResult) -> None:
        ev = lambda detail="", **meta: Evidence(source=src, detail=detail,  # noqa: E731
                                                 url=rec.get("seen_at", "") or rec.get("url", ""),
                                                 meta=meta)
        state_map = {"live_signal": SignalState.LIVE_SIGNAL,
                     "historical": SignalState.HISTORICAL,
                     "archived": SignalState.ARCHIVED,
                     "unverified": SignalState.UNVERIFIED}

        if rtype == "subdomain":
            if self._cap_reached(inv, AssetType.SUBDOMAIN, lim.max_subdomains):
                return
            host = normalize.normalize_domain(rec.get("value", ""))
            if not host:
                return
            roleinfo = subdomain_roles.classify_host(host)
            inv.upsert(AssetType.SUBDOMAIN, host, evidence=ev("subdomain"),
                       subdomain=host, domain=normalize.registrable_domain(host) or base,
                       subdomain_role=roleinfo["role"],
                       signal_state=state_map.get(rec.get("signal_state"), SignalState.UNVERIFIED))
        elif rtype == "domain":
            if self._cap_reached(inv, AssetType.DOMAIN, lim.max_domains):
                return
            host = normalize.normalize_domain(rec.get("value", ""))
            if not host:
                return
            dc = DomainClass.PRIMARY if host == base else DomainClass.RELATED
            inv.upsert(AssetType.DOMAIN, host, evidence=ev("domain"),
                       domain=host, domain_class=dc)
        elif rtype == "certificate":
            a = inv.upsert(AssetType.CERTIFICATE, rec.get("value", ""),
                           evidence=ev("certificate"),
                           attributes={"issuer": rec.get("issuer", ""),
                                       "not_before": rec.get("not_before", ""),
                                       "not_after": rec.get("not_after", ""),
                                       "sans": rec.get("sans", [])})
        elif rtype == "dns_record":
            host = normalize.normalize_domain(rec.get("host", ""))
            val = f"{rec.get('rr_type', '')} {rec.get('value', '')}".strip()
            a = inv.upsert(AssetType.DNS_RECORD, val, evidence=ev("dns"),
                           subdomain=host or "", domain=normalize.registrable_domain(host or "") or base,
                           attributes={"rr_type": rec.get("rr_type", ""),
                                       "host": host or "", "data": rec.get("value", "")})
        elif rtype == "ip":
            ip = normalize.normalize_ip(rec.get("value", ""))
            if ip and normalize.is_public_ip(ip):
                inv.upsert(AssetType.IP, ip, evidence=ev("ip"),
                           attributes={"host": rec.get("host", "")})
        elif rtype == "related_host":
            host = normalize.normalize_domain(rec.get("value", ""))
            if host:
                inv.upsert(AssetType.PUBLIC_SERVICE_REFERENCE, host, evidence=ev("dns"),
                           attributes={"rr_type": rec.get("rr_type", ""),
                                       "for_host": rec.get("host", "")})
        elif rtype in ("historical_url",):
            if self._cap_reached(inv, AssetType.HISTORICAL_ASSET, lim.max_urls):
                return
            url = normalize.normalize_url(rec.get("value", ""))
            if url:
                inv.upsert(AssetType.HISTORICAL_ASSET, url, evidence=ev("wayback"),
                           url=url, signal_state=SignalState.ARCHIVED,
                           attributes={"timestamp": rec.get("timestamp", ""),
                                       "mimetype": rec.get("mimetype", "")})
        elif rtype == "url":
            url = normalize.normalize_url(rec.get("value", ""))
            if not url:
                return
            host = normalize.host_of_url(url)
            inv.upsert(AssetType.WEBSITE, url, evidence=ev("website"), url=url,
                       subdomain=host or "", domain=normalize.registrable_domain(host or "") or base,
                       signal_state=SignalState.LIVE_SIGNAL)
        elif rtype == "document":
            if self._cap_reached(inv, AssetType.PUBLIC_FILE, lim.max_documents):
                return
            url = normalize.normalize_url(rec.get("value", ""))
            if url:
                inv.upsert(AssetType.PUBLIC_FILE, url, evidence=ev("document"), url=url,
                           attributes={"ext": rec.get("ext", ""),
                                       "timestamp": rec.get("timestamp", "")},
                           signal_state=state_map.get(rec.get("signal_state"), SignalState.UNVERIFIED))
        elif rtype == "repository":
            if self._cap_reached(inv, AssetType.REPOSITORY, lim.max_repositories):
                return
            inv.upsert(AssetType.REPOSITORY, rec.get("value", ""),
                       evidence=ev("repository"), url=rec.get("url", ""),
                       attributes={"description": rec.get("description", ""),
                                   "homepage": rec.get("homepage", ""),
                                   "stars": rec.get("stars", 0),
                                   "language": rec.get("language", ""),
                                   "relevant": rec.get("relevant", False)})
        elif rtype == "page":
            # A fetched page: register the website and stash for offline analysis.
            url = normalize.normalize_url(rec.get("value", ""))
            host = normalize.host_of_url(url or "")
            if url:
                a = inv.upsert(AssetType.WEBSITE, url, evidence=ev("website"), url=url,
                               subdomain=host or "", label=rec.get("title", ""),
                               domain=normalize.registrable_domain(host or "") or base,
                               signal_state=SignalState.LIVE_SIGNAL,
                               attributes={"status": rec.get("status", 0),
                                           "title": rec.get("title", "")})
                result.extra_signals.append({"type": "_page", "url": url,
                                             "host": host or "",
                                             "headers": rec.get("headers", {}),
                                             "body": rec.get("body", "")})
        elif rtype == "wellknown_file" and rec.get("name") == "security.txt":
            parsed = security_signals.parse_security_txt(rec.get("text", ""), rec.get("value", ""))
            result.security.append(parsed)
        elif rtype in ("sitemap_ref", "robots"):
            result.extra_signals.append(rec)

    # -- finalize (offline analysis, scope, graph, exposure, scoring) ------ #

    def _finalize(self, result: ReconResult, ctx: ReconContext, base: str) -> None:
        cfg = result.config
        inv = result.inventory

        # Offline analysis over fetched pages: technology + reference extraction.
        if cfg.enabled("technology") or cfg.enabled("metadata"):
            for sig in [s for s in result.extra_signals if s.get("type") == "_page"]:
                headers = sig.get("headers", {})
                body = sig.get("body", "")
                url = sig.get("url", "")
                site = inv.get(AssetType.WEBSITE, url)
                if cfg.enabled("technology"):
                    for t in tech.fingerprint(headers, body, url):
                        if site:
                            site.add_technology(t)
                    for hdr in security_signals.analyze_headers(headers, url):
                        result.security.append(hdr)
                # Reference extraction (also finds new hosts/docs/refs).
                for erec in extract.extract(body, base_domain=base, source="html", url=url):
                    self._ingest_extracted(erec, result, base)
                # Bug-bounty / status detection from page text + url.
                for bb in security_signals.detect_bug_bounty([body, url]):
                    result.security.append(bb)
                for sp in security_signals.detect_status_page(sig.get("host", ""), [body]):
                    result.security.append(sp)

        # Scope-classify every asset against the declared engagement scope.
        ctx.classifier().apply(inv.assets())

        # Build the attack-surface graph.
        if cfg.enabled("graph"):
            self._build_graph(result, base)

        # Exposure signals + observed public surface.
        if cfg.enabled("exposure"):
            result.exposure_signals = exposure.classify_exposure(inv, result.extra_signals)
        result.observed_surface = exposure.observed_public_surface(inv)

        # Technology timeline (history/standard/deep).
        if cfg.enabled("history"):
            result.technology_timeline = history.technology_timeline(inv)

        # Passive-recon relevance scoring.
        result.relevance = scoring.score_inventory(inv, base)

        # Drop the bulky raw page bodies from extra_signals before returning.
        result.extra_signals = [s for s in result.extra_signals if s.get("type") != "_page"]

    def _ingest_extracted(self, erec: Dict[str, Any], result: ReconResult,
                          base: str) -> None:
        """Fold an extract.extract() record into the inventory / extra signals."""
        inv = result.inventory
        lim = result.config.limits
        rtype = erec.get("type")
        src = erec.get("source", "html")
        if rtype in ("subdomain", "domain", "url", "email", "ip", "document"):
            # Reuse the same ingestion path for structural records.
            self._ingest_record(rtype if rtype != "email" else "email",
                                 erec, src, inv, base, lim, result)
            if rtype == "email":
                inv.upsert(AssetType.EMAIL, erec.get("value", ""),
                           evidence=Evidence(source=src, detail="public email"),
                           attributes={"domain": erec.get("domain", "")})
        elif rtype == "cloud_reference":
            inv.upsert(AssetType.CLOUD_REFERENCE, erec.get("value", ""),
                       evidence=Evidence(source=src, detail=f"cloud:{erec.get('provider')}"),
                       attributes={"provider": erec.get("provider", ""),
                                   "classification": erec.get("classification", "")})
        elif rtype == "api_reference":
            inv.upsert(AssetType.API, erec.get("value", ""),
                       evidence=Evidence(source=src, detail=f"api:{erec.get('kind')}"),
                       attributes={"kind": erec.get("kind", ""),
                                   "classification": erec.get("classification", "")})
        else:
            # package/pipeline/internal/secret signals are not assets.
            result.extra_signals.append(erec)

    def _build_graph(self, result: ReconResult, base: str) -> None:
        g = result.graph
        inv = result.inventory
        g.add_node(base, "domain", base)
        for a in inv:
            t = a.asset_type
            if t is AssetType.SUBDOMAIN:
                g.add_node(a.value, "subdomain", a.value, role=a.subdomain_role,
                           scope=a.scope.value)
                reg = a.domain or base
                g.add_node(reg, "domain", reg)
                g.add_edge(reg, a.value, graphmod.EDGE_HAS_SUBDOMAIN)
            elif t is AssetType.DOMAIN:
                g.add_node(a.value, "domain", a.value, scope=a.scope.value)
            elif t is AssetType.WEBSITE:
                g.add_node(a.value, "website", a.value, scope=a.scope.value)
                host = a.subdomain or normalize.host_of_url(a.url or a.value)
                if host:
                    g.add_node(host, "subdomain", host)
                    g.add_edge(host, a.value, graphmod.EDGE_HOSTS)
                for techrec in a.technologies:
                    name = str(techrec.get("name", ""))
                    if name:
                        g.add_node(f"tech:{name}", "technology", name)
                        g.add_edge(a.value, f"tech:{name}", graphmod.EDGE_RUNS,
                                   version=techrec.get("version", ""))
            elif t is AssetType.CERTIFICATE:
                cid = f"cert:{a.value}"
                g.add_node(cid, "certificate", a.attributes.get("issuer", a.value))
                for san in a.attributes.get("sans", []) or []:
                    g.add_node(san, "subdomain", san)
                    g.add_edge(san, cid, graphmod.EDGE_SECURED_BY)
                    g.add_edge(cid, san, graphmod.EDGE_COVERS)
            elif t is AssetType.DNS_RECORD:
                host = a.attributes.get("host", "")
                rr = a.attributes.get("rr_type", "")
                data = a.attributes.get("data", "")
                if host and data:
                    if rr in ("A", "AAAA") and normalize.is_public_ip(data):
                        g.add_node(data, "ip", data)
                        g.add_edge(host, data, graphmod.EDGE_RESOLVES_TO)
            elif t is AssetType.PUBLIC_SERVICE_REFERENCE:
                rr = a.attributes.get("rr_type", "")
                forhost = a.attributes.get("for_host", "")
                if forhost:
                    kind = graphmod.EDGE_USES_NAMESERVER if rr == "NS" else (
                        graphmod.EDGE_USES_MX if rr == "MX" else graphmod.EDGE_REFERENCES)
                    g.add_node(a.value, "nameserver" if rr in ("NS", "MX") else "host", a.value)
                    g.add_edge(forhost, a.value, kind)
            elif t is AssetType.REPOSITORY:
                rid = f"repo:{a.value}"
                g.add_node(rid, "repository", a.value)
                # repository --REFERENCES--> base domain when it looks relevant.
                if a.attributes.get("relevant"):
                    g.add_edge(rid, base, graphmod.EDGE_REFERENCES)
            elif t is AssetType.CLOUD_REFERENCE:
                cid = f"cloud:{a.value}"
                g.add_node(cid, "cloud_reference", a.value,
                           provider=a.attributes.get("provider", ""))
                g.add_edge(base, cid, graphmod.EDGE_REFERENCES)
            elif t is AssetType.PUBLIC_FILE:
                did = f"doc:{a.value}"
                g.add_node(did, "document", a.value)
                host = normalize.host_of_url(a.url or a.value)
                if host:
                    g.add_node(host, "subdomain", host)
                    g.add_edge(host, did, graphmod.EDGE_REFERENCES)


async def run_recon(target: str, ctx: ReconContext, *,
                    mode: ReconMode = ReconMode.STANDARD,
                    collectors: Optional[List[Collector]] = None,
                    client: Optional[Any] = None) -> ReconResult:
    """Module-level convenience wrapper around :class:`ReconPipeline`."""
    pipeline = ReconPipeline(collectors)
    return await pipeline.run(target, ctx, config=ReconConfig(mode=mode), client=client)
