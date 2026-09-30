"""
cve_tracker.enrichment.references — classify reference URLs (data only).

A CVE's references are a pile of URLs with optional source-supplied tags. This
classifier assigns each a :class:`ReferenceType` from the domain and path and
any tags — so the formatter can show '🔗 Advisory' vs '🧪 PoC' and the
exploit-status engine can count exploit-ish references.

Hard rule (rule §12/§31): classification is the ONLY thing that happens to a
reference URL. Nothing here fetches, downloads, resolves, or executes anything.
The URLs are treated as opaque strings.
"""

from __future__ import annotations

from typing import List, Optional

from ..constants import (
    EXPLOIT_DB_HOSTS,
    POC_HINT_HOSTS,
    VENDOR_ADVISORY_HOSTS,
    PATCH_HINT_KEYWORDS,
    ADVISORY_HINT_KEYWORDS,
    EXPLOIT_HINT_KEYWORDS,
    RESEARCH_HINT_KEYWORDS,
    MAILING_LIST_HINT_KEYWORDS,
)
from ..enums import ReferenceType
from ..models import Reference
from ..utils import normalize_url, url_host, dedupe_preserve_order

# Source-supplied tag → our type (NVD/CVE.org use these controlled tags).
_TAG_MAP = {
    "patch": ReferenceType.PATCH,
    "vendor advisory": ReferenceType.VENDOR_ADVISORY,
    "third party advisory": ReferenceType.THIRD_PARTY,
    "exploit": ReferenceType.EXPLOIT,
    "issue tracking": ReferenceType.ISSUE_TRACKER,
    "mailing list": ReferenceType.MAILING_LIST,
    "technical description": ReferenceType.TECHNICAL,
    "release notes": ReferenceType.PATCH,
    "mitigation": ReferenceType.MITIGATION,
    "product": ReferenceType.PRODUCT,
    "us government resource": ReferenceType.ADVISORY,
    "press/media coverage": ReferenceType.NEWS,
    "broken link": ReferenceType.UNKNOWN,
    "not applicable": ReferenceType.UNKNOWN,
}


def classify_reference(url: str, *, tags: Optional[List[str]] = None,
                       title: str = "", source: str = "") -> Reference:
    """Classify a single reference. Precedence: explicit exploit/patch tags >
    known hosts > URL/path keywords > generic advisory/blog fallback."""
    norm = normalize_url(url) or (url or "").strip()
    host = url_host(norm)
    low_url = norm.lower()
    tag_list = [str(t).strip().lower() for t in (tags or []) if str(t).strip()]

    ref_type = _from_tags(tag_list)
    if ref_type is None:
        ref_type = _from_host(host, low_url)
    if ref_type is None:
        ref_type = _from_keywords(low_url, title)
    if ref_type is None:
        ref_type = ReferenceType.UNKNOWN

    return Reference(url=norm, ref_type=ref_type.value, title=(title or "").strip(),
                     tags=dedupe_preserve_order(tag_list), source=source)


def _from_tags(tags: List[str]):
    # Exploit/patch tags are the strongest signal.
    for strong in ("exploit", "patch", "vendor advisory", "mitigation"):
        if strong in tags:
            return _TAG_MAP[strong]
    for t in tags:
        if t in _TAG_MAP:
            return _TAG_MAP[t]
    return None


def _from_host(host: str, low_url: str):
    if not host:
        return None
    if host in EXPLOIT_DB_HOSTS:
        return ReferenceType.EXPLOIT_DB
    if host in VENDOR_ADVISORY_HOSTS:
        return ReferenceType.VENDOR_ADVISORY
    if host in POC_HINT_HOSTS:
        # A GitHub/GitLab link is a repo unless the path clearly names an exploit.
        if any(k in low_url for k in EXPLOIT_HINT_KEYWORDS):
            return ReferenceType.POC
        return ReferenceType.GITHUB_REPO
    if any(host.endswith(s) for s in (".gov",)):
        return ReferenceType.ADVISORY
    return None


def _from_keywords(low_url: str, title: str):
    hay = f"{low_url} {(title or '').lower()}"
    if any(k in hay for k in EXPLOIT_HINT_KEYWORDS):
        return ReferenceType.POC
    if any(k in low_url for k in PATCH_HINT_KEYWORDS):
        return ReferenceType.PATCH
    if any(k in hay for k in MAILING_LIST_HINT_KEYWORDS):
        return ReferenceType.MAILING_LIST
    if any(k in hay for k in ADVISORY_HINT_KEYWORDS):
        return ReferenceType.ADVISORY
    if any(k in hay for k in RESEARCH_HINT_KEYWORDS):
        return ReferenceType.RESEARCH
    return None


def classify_references(raw_refs: List, *, source: str = "") -> List[Reference]:
    """Classify a list of references. Each item may be a string URL or a dict
    with url/tags/name keys (NVD/CVE.org shapes)."""
    out: List[Reference] = []
    for item in raw_refs or []:
        if isinstance(item, str):
            ref = classify_reference(item, source=source)
        elif isinstance(item, dict):
            url = item.get("url") or item.get("reference") or item.get("name") or ""
            tags = item.get("tags") or item.get("type") or []
            if isinstance(tags, str):
                tags = [tags]
            title = item.get("name") or item.get("title") or ""
            if title == url:
                title = ""
            ref = classify_reference(url, tags=tags, title=title, source=source)
        else:
            continue
        if ref.url:
            out.append(ref)
    return merge_references(out)


def merge_references(*groups) -> List[Reference]:
    """Union references de-duplicated by normalized URL, unioning tags and
    keeping the most specific (non-UNKNOWN) type seen."""
    flat: List[Reference] = []
    for g in groups:
        if isinstance(g, list):
            flat.extend(g)
        elif isinstance(g, Reference):
            flat.append(g)
    by_url = {}
    order = []
    specificity = {
        ReferenceType.UNKNOWN.value: 0,
        ReferenceType.THIRD_PARTY.value: 1,
        ReferenceType.NEWS.value: 1,
        ReferenceType.BLOG.value: 1,
        ReferenceType.MAILING_LIST.value: 2,
        ReferenceType.RESEARCH.value: 2,
        ReferenceType.TECHNICAL.value: 3,
        ReferenceType.ISSUE_TRACKER.value: 3,
        ReferenceType.PRODUCT.value: 3,
        ReferenceType.GITHUB_REPO.value: 4,
        ReferenceType.ADVISORY.value: 5,
        ReferenceType.MITIGATION.value: 5,
        ReferenceType.VENDOR_ADVISORY.value: 6,
        ReferenceType.PATCH.value: 7,
        ReferenceType.POC.value: 8,
        ReferenceType.EXPLOIT_DB.value: 9,
        ReferenceType.EXPLOIT.value: 9,
    }
    for r in flat:
        if not r or not r.url:
            continue
        key = r.url
        if key not in by_url:
            by_url[key] = Reference(url=r.url, ref_type=r.ref_type,
                                    title=r.title, tags=list(r.tags), source=r.source)
            order.append(key)
        else:
            cur = by_url[key]
            if specificity.get(r.ref_type, 0) > specificity.get(cur.ref_type, 0):
                cur.ref_type = r.ref_type
            cur.tags = dedupe_preserve_order(cur.tags + r.tags)
            if not cur.title and r.title:
                cur.title = r.title
    return [by_url[k] for k in order]


def count_by_type(refs: List[Reference]) -> dict:
    counts = {}
    for r in refs or []:
        counts[r.ref_type] = counts.get(r.ref_type, 0) + 1
    return counts
