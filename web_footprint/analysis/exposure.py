"""
web_footprint.analysis.exposure — classify public-exposure signals and report
the observed public surface.

This module answers two spec requirements without ever crossing into judgement:

  * PUBLIC EXPOSURE CATEGORIES (spec §47). Each notable observation is bucketed
    into a category — DOMAIN / DOCUMENT / METADATA / INFRASTRUCTURE / TECHNOLOGY
    / REPOSITORY / HISTORICAL / PUBLIC_IDENTIFIER exposure. A category says *what
    kind of public footprint* a signal is, not that it is a weakness.

  * OBSERVED PUBLIC SURFACE (spec §46). Instead of assigning a "security
    maturity" score from passive data — which the spec forbids — the engine
    reports factual metrics: counts of domains, subdomains, websites, documents,
    repositories, technologies, certificates and historical assets. Numbers, not
    a grade.

Pure functions, standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..assets import Asset, AssetType, AttackSurfaceInventory, ExposureCategory


@dataclass
class ExposureSignal:
    category: ExposureCategory
    subject: str
    detail: str = ""
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"category": self.category.value, "subject": self.subject,
                "detail": self.detail, "sources": sorted(set(self.sources)),
                "confidence": round(self.confidence, 1)}


# Which asset type maps to which exposure category.
_TYPE_CATEGORY = {
    AssetType.DOMAIN: ExposureCategory.DOMAIN,
    AssetType.SUBDOMAIN: ExposureCategory.DOMAIN,
    AssetType.WEBSITE: ExposureCategory.DOMAIN,
    AssetType.API: ExposureCategory.TECHNOLOGY,
    AssetType.DOCUMENTATION: ExposureCategory.DOCUMENT,
    AssetType.PUBLIC_FILE: ExposureCategory.DOCUMENT,
    AssetType.REPOSITORY: ExposureCategory.REPOSITORY,
    AssetType.CERTIFICATE: ExposureCategory.INFRASTRUCTURE,
    AssetType.IP: ExposureCategory.INFRASTRUCTURE,
    AssetType.DNS_RECORD: ExposureCategory.INFRASTRUCTURE,
    AssetType.CLOUD_REFERENCE: ExposureCategory.INFRASTRUCTURE,
    AssetType.EMAIL: ExposureCategory.PUBLIC_IDENTIFIER,
    AssetType.HISTORICAL_ASSET: ExposureCategory.HISTORICAL,
    AssetType.STATUS_PAGE: ExposureCategory.INFRASTRUCTURE,
    AssetType.PORTAL: ExposureCategory.DOMAIN,
    AssetType.BLOG: ExposureCategory.DOMAIN,
    AssetType.PUBLIC_SERVICE_REFERENCE: ExposureCategory.INFRASTRUCTURE,
}


def classify_exposure(inventory: AttackSurfaceInventory,
                      extra_signals: List[Dict[str, Any]] = None) -> List[ExposureSignal]:
    """Turn the inventory (and any extra signal records) into exposure signals.

    ``extra_signals`` may include metadata records (document authors/software),
    internal-naming signals and redacted secret signals — each of which maps to
    METADATA or PUBLIC_IDENTIFIER exposure."""
    out: List[ExposureSignal] = []
    for asset in inventory:
        category = _TYPE_CATEGORY.get(asset.asset_type)
        if category is None:
            continue
        # A historical-only signal is HISTORICAL exposure regardless of type.
        if asset.signal_state.value in ("historical", "archived"):
            category = ExposureCategory.HISTORICAL
        if asset.technologies:
            out.append(ExposureSignal(
                ExposureCategory.TECHNOLOGY, asset.value,
                detail=f"{len(asset.technologies)} technology signal(s)",
                sources=asset.sources, confidence=asset.confidence))
        out.append(ExposureSignal(category, asset.value,
                                  detail=asset.subdomain_role or asset.asset_type.value,
                                  sources=asset.sources, confidence=asset.confidence))

    for rec in extra_signals or []:
        rtype = rec.get("type")
        if rtype in ("document_metadata", "metadata"):
            out.append(ExposureSignal(ExposureCategory.METADATA,
                                      str(rec.get("value", "")),
                                      detail=str(rec.get("detail", "")),
                                      sources=[rec.get("source", "extract")]))
        elif rtype == "internal_naming_signal":
            out.append(ExposureSignal(ExposureCategory.METADATA,
                                      str(rec.get("value", "")),
                                      detail="internal-naming signal",
                                      sources=[rec.get("source", "extract")]))
        elif rtype == "secret_signal":
            out.append(ExposureSignal(ExposureCategory.PUBLIC_IDENTIFIER,
                                      str(rec.get("kind", "secret")),
                                      detail=f"redacted secret-like string "
                                             f"({rec.get('redacted', '')}); not validated",
                                      sources=[rec.get("source", "extract")]))
        elif rtype == "email":
            out.append(ExposureSignal(ExposureCategory.PUBLIC_IDENTIFIER,
                                      str(rec.get("value", "")),
                                      detail="public email",
                                      sources=[rec.get("source", "extract")]))
    return out


def observed_public_surface(inventory: AttackSurfaceInventory) -> Dict[str, Any]:
    """Factual metrics of the observed public surface (spec §46). No grade."""
    def n(*types: AssetType) -> int:
        return len(inventory.of_type(*types))

    tech_names = set()
    for a in inventory:
        for t in a.technologies:
            name = str(t.get("name", "")).lower()
            if name:
                tech_names.add(name)

    return {
        "domains": n(AssetType.DOMAIN),
        "subdomains": n(AssetType.SUBDOMAIN),
        "websites": n(AssetType.WEBSITE, AssetType.PORTAL, AssetType.BLOG),
        "apis": n(AssetType.API),
        "documents": n(AssetType.DOCUMENTATION, AssetType.PUBLIC_FILE),
        "repositories": n(AssetType.REPOSITORY),
        "certificates": n(AssetType.CERTIFICATE),
        "ips": n(AssetType.IP),
        "dns_records": n(AssetType.DNS_RECORD),
        "cloud_references": n(AssetType.CLOUD_REFERENCE),
        "emails": n(AssetType.EMAIL),
        "technologies": len(tech_names),
        "historical_assets": n(AssetType.HISTORICAL_ASSET) + sum(
            1 for a in inventory if a.signal_state.value in ("historical", "archived")),
        "total_assets": len(inventory),
    }


def summarize_exposure(signals: List[ExposureSignal]) -> Dict[str, int]:
    """Count exposure signals per category."""
    out: Dict[str, int] = {}
    for s in signals:
        out[s.category.value] = out.get(s.category.value, 0) + 1
    return out
