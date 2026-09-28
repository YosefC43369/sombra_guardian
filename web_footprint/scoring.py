"""
web_footprint.scoring — the PassiveReconRelevanceScore (spec §45).

How *relevant* is a discovered asset to the target, and how well is that
relevance corroborated? This module answers that with a 0–100 score built from
explicit, inspectable factors:

  * domain relevance      — is the asset within the target's registrable domain?
  * asset relevance       — does its type carry attack-surface weight?
  * source quality        — how authoritative are the sources that reported it?
  * cross-source corroboration — do independent sources agree?
  * historical consistency — is it seen now, historically, or only once?
  * technology / document / infrastructure evidence — supporting signal breadth.

Two things this score is NOT, both stated in the spec:
  * It is NOT a vulnerability score (spec §45). A high relevance score means
    "this is very likely part of the target's public surface and well
    corroborated", never "this is exploitable".
  * It is NOT a black box. Every point is attributable to a listed factor, and
    the same evidence always yields the same score (determinism matters — this
    feeds reports).

Pure functions, standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .assets import Asset, AssetType, ScopeStatus
from . import normalize

# --- tunable, inspectable weights ------------------------------------------ #
W_DOMAIN_RELEVANCE = 30.0
W_ASSET_RELEVANCE = 15.0
W_SOURCE_QUALITY = 20.0
W_CORROBORATION = 15.0
W_HISTORICAL = 8.0
W_TECHNOLOGY = 6.0
W_INFRASTRUCTURE = 6.0

# Attack-surface weight per asset type (0..1), scaling the asset-relevance term.
_ASSET_WEIGHT = {
    AssetType.SUBDOMAIN: 1.0, AssetType.WEBSITE: 1.0, AssetType.API: 1.0,
    AssetType.PORTAL: 0.95, AssetType.DOCUMENTATION: 0.8, AssetType.REPOSITORY: 0.8,
    AssetType.CERTIFICATE: 0.7, AssetType.IP: 0.7, AssetType.CLOUD_REFERENCE: 0.75,
    AssetType.DOMAIN: 0.9, AssetType.DNS_RECORD: 0.5, AssetType.PUBLIC_FILE: 0.7,
    AssetType.EMAIL: 0.5, AssetType.STATUS_PAGE: 0.4, AssetType.BLOG: 0.5,
    AssetType.PUBLIC_SERVICE_REFERENCE: 0.5, AssetType.HISTORICAL_ASSET: 0.5,
    AssetType.UNKNOWN: 0.3,
}

BANDS = [(80.0, "high"), (60.0, "elevated"), (40.0, "moderate"),
         (20.0, "low"), (0.0, "minimal")]


@dataclass
class ScoreFactor:
    label: str
    contribution: float
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "contribution": round(self.contribution, 1),
                "detail": self.detail}


@dataclass
class RelevanceScore:
    score: float
    band: str
    factors: List[ScoreFactor] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"score": round(self.score, 1), "band": self.band,
                "factors": [f.to_dict() for f in self.factors],
                "note": "passive-recon relevance, not a vulnerability score"}


def _band(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "minimal"


def score_asset(asset: Asset, target_domain: str) -> RelevanceScore:
    """Compute the PassiveReconRelevanceScore for one asset."""
    factors: List[ScoreFactor] = []
    base = normalize.registrable_domain(target_domain) or (target_domain or "").lower()

    # 1) Domain relevance.
    host = asset.subdomain or asset.domain or (
        asset.value if asset.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN) else "")
    host = normalize.normalize_domain(host) or normalize.host_of_url(asset.url or "") or ""
    if host and base and normalize.is_subdomain_of(host, base):
        dr = W_DOMAIN_RELEVANCE
        detail = f"within target domain {base}"
    elif asset.scope is ScopeStatus.IN_SCOPE:
        dr = W_DOMAIN_RELEVANCE * 0.8
        detail = "declared in scope"
    elif asset.scope is ScopeStatus.OUT_OF_SCOPE:
        dr = 0.0
        detail = "declared out of scope"
    else:
        dr = W_DOMAIN_RELEVANCE * 0.3
        detail = "relationship to target unverified"
    factors.append(ScoreFactor("domain_relevance", dr, detail))

    # 2) Asset relevance (type weight).
    aw = _ASSET_WEIGHT.get(asset.asset_type, 0.3)
    factors.append(ScoreFactor("asset_relevance", W_ASSET_RELEVANCE * aw,
                               f"{asset.asset_type.value} weight {aw:.2f}"))

    # 3) Source quality (best evidence quality).
    best_q = max((e.quality for e in asset.evidence), default=0.0)
    factors.append(ScoreFactor("source_quality", W_SOURCE_QUALITY * best_q,
                               f"best source quality {best_q:.2f}"))

    # 4) Cross-source corroboration.
    n_sources = len(asset.sources)
    corr = min(1.0, (n_sources - 1) / 3.0) if n_sources > 1 else 0.0
    factors.append(ScoreFactor("corroboration", W_CORROBORATION * corr,
                               f"{n_sources} independent source(s)"))

    # 5) Historical consistency.
    state = asset.signal_state.value
    hist = 1.0 if state == "live_signal" else (0.6 if state in ("historical", "archived") else 0.3)
    factors.append(ScoreFactor("historical_consistency", W_HISTORICAL * hist,
                               f"signal state {state}"))

    # 6) Technology evidence.
    if asset.technologies:
        factors.append(ScoreFactor("technology_evidence",
                                   W_TECHNOLOGY * min(1.0, len(asset.technologies) / 3.0),
                                   f"{len(asset.technologies)} technology signal(s)"))

    # 7) Infrastructure evidence (a resolving IP / cert / DNS attribute present).
    infra = any(k in asset.attributes for k in ("ip", "certificate", "resolves_to")) \
        or asset.asset_type in (AssetType.CERTIFICATE, AssetType.IP, AssetType.DNS_RECORD)
    if infra:
        factors.append(ScoreFactor("infrastructure_evidence", W_INFRASTRUCTURE,
                                   "infrastructure attribute present"))

    total = max(0.0, min(100.0, sum(f.contribution for f in factors)))
    return RelevanceScore(total, _band(total), factors)


def score_inventory(inventory, target_domain: str) -> Dict[str, Any]:
    """Score every asset and return per-asset scores plus a run-level summary."""
    scored = []
    for asset in inventory:
        rs = score_asset(asset, target_domain)
        scored.append((asset, rs))
    scored.sort(key=lambda pair: -pair[1].score)
    if scored:
        avg = sum(rs.score for _, rs in scored) / len(scored)
        top = scored[0][1].score
    else:
        avg = top = 0.0
    return {
        "target": target_domain,
        "asset_count": len(scored),
        "average_relevance": round(avg, 1),
        "max_relevance": round(top, 1),
        "note": "passive-recon relevance scores; NOT vulnerability scores",
        "assets": [{"asset": a.value, "type": a.asset_type.value,
                    "relevance": rs.to_dict()} for a, rs in scored],
    }
