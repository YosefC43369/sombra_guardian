"""
cve_tracker.enrichment.cpe — CPE parsing and affected-product extraction.

Turns CPE 2.3 URI bindings (and legacy 2.2) into :class:`AffectedProduct`
records, and decodes the NVD ``configurations`` node (a nested AND/OR tree of
cpeMatch objects with version ranges) into a flat product list. Vendor/product
tokens in CPE use ``\\`` escaping and ``*``/``-`` wildcards — we unescape and
normalize them to readable names.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..constants import CPE22_RE, CPE23_RE
from ..models import AffectedProduct
from ..utils import dedupe_preserve_order

_CPE_UNESCAPE_RE = re.compile(r"\\(.)")


def _unescape(token: str) -> str:
    if not token:
        return ""
    return _CPE_UNESCAPE_RE.sub(r"\1", token)


def _clean_token(token: str) -> str:
    """CPE tokens use '*'=ANY, '-'=NA, and '_' for spaces. Render to a human
    string; wildcards become empty."""
    if token in ("*", "-", ""):
        return ""
    return _unescape(token).replace("_", " ").strip()


def parse_cpe(cpe: str) -> Optional[AffectedProduct]:
    """Parse a single CPE URI into an AffectedProduct (vendor/product/version),
    or None if it isn't a CPE. Part 'a' is application, 'o' OS, 'h' hardware."""
    if not cpe:
        return None
    text = cpe.strip()
    m = CPE23_RE.match(text)
    if m:
        vendor = _clean_token(m.group("vendor"))
        product = _clean_token(m.group("product"))
        version = _clean_token(m.group("version"))
        ap = AffectedProduct(vendor=vendor, product=product, cpe=text)
        if version:
            ap.versions_affected = [version]
        return ap
    m = CPE22_RE.match(text)
    if m:
        ap = AffectedProduct(
            vendor=_clean_token(m.group("vendor")),
            product=_clean_token(m.group("product")),
            cpe=text,
        )
        ver = _clean_token(m.group("version") or "")
        if ver:
            ap.versions_affected = [ver]
        return ap
    return None


def _apply_range(ap: AffectedProduct, match: Dict) -> None:
    """Copy NVD cpeMatch version-range fields onto the product."""
    ap.version_start_including = str(match.get("versionStartIncluding", "") or "")
    ap.version_start_excluding = str(match.get("versionStartExcluding", "") or "")
    ap.version_end_including = str(match.get("versionEndIncluding", "") or "")
    ap.version_end_excluding = str(match.get("versionEndExcluding", "") or "")


def _walk_nodes(nodes: List[Dict], source: str, out: List[AffectedProduct]) -> None:
    """Recursively walk an NVD configurations AND/OR node tree collecting every
    vulnerable cpeMatch."""
    for node in nodes or []:
        for match in node.get("cpeMatch", []) or []:
            if not match.get("vulnerable", False):
                continue
            criteria = match.get("criteria") or match.get("cpe23Uri") or ""
            ap = parse_cpe(criteria)
            if ap is None:
                continue
            ap.source = source
            ap.default_status = "affected"
            _apply_range(ap, match)
            out.append(ap)
        # Nested children (AND of ORs, etc.)
        children = node.get("children") or node.get("nodes")
        if children:
            _walk_nodes(children, source, out)


def products_from_nvd_configurations(configurations, *, source: str = "nvd") -> List[AffectedProduct]:
    """Decode the NVD 2.0 ``configurations`` field into products. Accepts both
    the list form (2.0 API) and the legacy dict-with-nodes form."""
    out: List[AffectedProduct] = []
    if not configurations:
        return out
    if isinstance(configurations, dict):
        configurations = [configurations]
    for cfg in configurations:
        nodes = cfg.get("nodes") if isinstance(cfg, dict) else None
        if nodes:
            _walk_nodes(nodes, source, out)
    return merge_products(out)


def products_from_cpe_list(cpes: List[str], *, source: str = "") -> List[AffectedProduct]:
    out: List[AffectedProduct] = []
    for cpe in cpes or []:
        ap = parse_cpe(cpe)
        if ap:
            ap.source = source
            out.append(ap)
    return merge_products(out)


def merge_products(*groups) -> List[AffectedProduct]:
    """Union products across sources, de-duplicated by vendor/product key,
    unioning their affected/fixed version lists and keeping the first non-empty
    range bounds."""
    by_key: Dict[str, AffectedProduct] = {}
    # Allow both merge_products(list) and merge_products(list_a, list_b).
    flat: List[AffectedProduct] = []
    for g in groups:
        if isinstance(g, list):
            flat.extend(g)
        elif isinstance(g, AffectedProduct):
            flat.append(g)
    for ap in flat:
        if ap is None or (not ap.vendor and not ap.product):
            continue
        key = ap.key
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = AffectedProduct(
                vendor=ap.vendor, product=ap.product, cpe=ap.cpe,
                versions_affected=list(ap.versions_affected),
                versions_fixed=list(ap.versions_fixed),
                version_start_including=ap.version_start_including,
                version_start_excluding=ap.version_start_excluding,
                version_end_including=ap.version_end_including,
                version_end_excluding=ap.version_end_excluding,
                default_status=ap.default_status or "affected",
                source=ap.source,
            )
        else:
            existing.versions_affected = dedupe_preserve_order(
                existing.versions_affected + ap.versions_affected)
            existing.versions_fixed = dedupe_preserve_order(
                existing.versions_fixed + ap.versions_fixed)
            for f in ("version_start_including", "version_start_excluding",
                      "version_end_including", "version_end_excluding"):
                if not getattr(existing, f) and getattr(ap, f):
                    setattr(existing, f, getattr(ap, f))
            if not existing.cpe and ap.cpe:
                existing.cpe = ap.cpe
    return list(by_key.values())


def format_product_label(ap: AffectedProduct) -> str:
    """'Microsoft Windows 11' style label with a version range hint."""
    parts = [p for p in (ap.vendor, ap.product) if p]
    label = " ".join(parts) if parts else (ap.cpe or "")
    rng = version_range_label(ap)
    return f"{label} {rng}".strip() if rng else label


def version_range_label(ap: AffectedProduct) -> str:
    """A compact '< 2.0' / '>= 1.0, < 2.0' style range, or '' if none."""
    bits: List[str] = []
    if ap.version_start_including:
        bits.append(f">= {ap.version_start_including}")
    elif ap.version_start_excluding:
        bits.append(f"> {ap.version_start_excluding}")
    if ap.version_end_including:
        bits.append(f"<= {ap.version_end_including}")
    elif ap.version_end_excluding:
        bits.append(f"< {ap.version_end_excluding}")
    if not bits and ap.versions_affected:
        # explicit single versions
        vs = ", ".join(ap.versions_affected[:3])
        return f"({vs})" if vs else ""
    return f"({', '.join(bits)})" if bits else ""
