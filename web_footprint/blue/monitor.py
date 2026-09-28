"""
web_footprint.blue.monitor — the defensive (blue-team) 20%.

The engine's primary purpose is red-team passive reconnaissance; this module is
the deliberately smaller defensive companion (spec §48). It reuses the exact same
passive recon output — no new collection posture — to give a defender:

  * a defensive asset inventory (spec §49) they can reconcile against their own
    authoritative inventory,
  * exposure monitoring by diffing today's snapshot against a stored one and
    raising factual alerts on what changed (spec §50, §54),
  * brand / impersonation monitoring via look-alike domain detection (spec §51),
  * IOC enrichment hand-off: public identifiers passed to the repo's existing
    threat-intelligence modules WITHOUT being pre-judged as malicious (spec §52),
  * public security-posture signals surfaced as facts, never a rating (spec §53).

Nothing here rates an organization or crosses into active testing. Standard
library only; the recon itself is delegated to :class:`WebFootprintEngine`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..assets import AssetType, AttackSurfaceInventory
from .. import normalize, history

if TYPE_CHECKING:  # avoid an import cycle at runtime
    from ..engine import WebFootprintEngine
    from ..pipeline import ReconResult


class AlertKind(str, Enum):
    NEW_PUBLIC_ASSET = "NEW_PUBLIC_ASSET"
    PUBLIC_DOCUMENT_CHANGED = "PUBLIC_DOCUMENT_CHANGED"
    DOMAIN_CHANGED = "DOMAIN_CHANGED"
    CERTIFICATE_CHANGED = "CERTIFICATE_CHANGED"
    PUBLIC_REPOSITORY_CHANGED = "PUBLIC_REPOSITORY_CHANGED"
    POTENTIAL_IMPERSONATION = "POTENTIAL_IMPERSONATION"
    POTENTIAL_EXPOSURE = "POTENTIAL_EXPOSURE"


@dataclass
class Alert:
    kind: AlertKind
    subject: str
    detail: str = ""
    sources: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind.value, "subject": self.subject,
                "detail": self.detail, "sources": sorted(set(self.sources))}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Asset types whose change maps to a specific alert kind.
_CHANGE_ALERT = {
    "certificate": AlertKind.CERTIFICATE_CHANGED,
    "repository": AlertKind.PUBLIC_REPOSITORY_CHANGED,
    "public_file": AlertKind.PUBLIC_DOCUMENT_CHANGED,
    "documentation": AlertKind.PUBLIC_DOCUMENT_CHANGED,
    "domain": AlertKind.DOMAIN_CHANGED,
    "subdomain": AlertKind.DOMAIN_CHANGED,
}


class BlueTeamMonitor:
    def __init__(self, engine: "WebFootprintEngine") -> None:
        self.engine = engine

    async def run_snapshot(self, target: str, ctx: Any, **kw: Any) -> "ReconResult":
        """Run a passive recon and return the result (its inventory is the
        snapshot source)."""
        return await self.engine.recon(target, ctx, **kw)

    # -- defensive inventory (spec §49) ------------------------------------ #

    @staticmethod
    def defensive_inventory(result: "ReconResult") -> Dict[str, Any]:
        inv = result.inventory

        def vals(*types: AssetType) -> List[str]:
            return sorted(a.value for a in inv.of_type(*types))

        techs = sorted({str(t.get("name", "")) for a in inv for t in a.technologies
                        if t.get("name")})
        return {
            "target": result.base_domain,
            "known_domains": vals(AssetType.DOMAIN),
            "known_subdomains": vals(AssetType.SUBDOMAIN),
            "known_websites": vals(AssetType.WEBSITE, AssetType.PORTAL, AssetType.BLOG),
            "known_repositories": vals(AssetType.REPOSITORY),
            "known_documents": vals(AssetType.PUBLIC_FILE, AssetType.DOCUMENTATION),
            "known_technologies": techs,
            "known_certificates": vals(AssetType.CERTIFICATE),
            "generated_at": round(result.finished_at, 3),
        }

    # -- exposure monitoring (spec §50, §54) ------------------------------- #

    @staticmethod
    def compare(current: "ReconResult",
                previous_snapshot: Optional[Dict[str, Any]]) -> List[Alert]:
        """Diff the current inventory against a stored snapshot and raise
        factual alerts. A previous snapshot of None yields no alerts (first
        run establishes the baseline)."""
        if not previous_snapshot:
            return []
        cur = history.snapshot(current.inventory)
        changes = history.diff_snapshots(cur, previous_snapshot)
        alerts: List[Alert] = []
        for ch in changes:
            if ch.kind is history.ChangeKind.ADDED:
                alerts.append(Alert(AlertKind.NEW_PUBLIC_ASSET, ch.value,
                                    f"new {ch.asset_type} observed"))
            elif ch.kind in (history.ChangeKind.CHANGED, history.ChangeKind.REAPPEARED):
                kind = _CHANGE_ALERT.get(ch.asset_type, AlertKind.NEW_PUBLIC_ASSET)
                alerts.append(Alert(kind, ch.value, ch.detail or ch.kind.value))
        return alerts

    # -- brand / impersonation monitoring (spec §51) ----------------------- #

    @staticmethod
    def brand_monitor(base_domain: str, candidate_domains: List[str], *,
                      known_domains: Optional[List[str]] = None,
                      max_distance: int = 2) -> List[Alert]:
        """Flag look-alike registrable domains that are neither the base nor a
        known-good domain. Uses edit distance on the registrable label plus a
        substring check for brand-embedding (``example-support.com``)."""
        base = normalize.registrable_domain(base_domain) or (base_domain or "").lower()
        base_label = base.split(".", 1)[0] if base else ""
        known = {normalize.registrable_domain(d) or (d or "").lower()
                 for d in (known_domains or [])}
        known.add(base)
        alerts: List[Alert] = []
        seen = set()
        for cand in candidate_domains:
            reg = normalize.registrable_domain(cand)
            if not reg or reg in known or reg in seen:
                continue
            label = reg.split(".", 1)[0]
            dist = _levenshtein(label, base_label)
            embeds = base_label and base_label in label and label != base_label
            if base_label and (0 < dist <= max_distance or embeds):
                seen.add(reg)
                alerts.append(Alert(
                    AlertKind.POTENTIAL_IMPERSONATION, reg,
                    f"look-alike of {base} (label distance {dist}"
                    f"{'; embeds brand' if embeds else ''}) — verify before acting"))
        return alerts

    # -- IOC enrichment hand-off (spec §52) -------------------------------- #

    @staticmethod
    def ioc_handoff(result: "ReconResult") -> Dict[str, List[str]]:
        """Collect public identifiers for the repo's threat-intel modules. These
        are NOT classified as malicious here (spec §52) — they are candidates for
        enrichment, handed off as-is."""
        inv = result.inventory
        domains = sorted({a.value for a in inv.of_type(AssetType.DOMAIN, AssetType.SUBDOMAIN)})
        ips = sorted({a.value for a in inv.of_type(AssetType.IP)})
        urls = sorted({a.url or a.value for a in inv.of_type(AssetType.WEBSITE)})
        return {"domains": domains, "ips": ips, "urls": urls,
                "note": "candidates for enrichment; not pre-classified as malicious"}

    # -- posture signals (spec §53) ---------------------------------------- #

    @staticmethod
    def posture_signals(result: "ReconResult") -> Dict[str, Any]:
        """Surface the collected security signals as facts (no rating)."""
        return {
            "security_signals": result.security,
            "note": "factual signals only; not converted to a security rating",
        }
