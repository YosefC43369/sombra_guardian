"""
cve_tracker.fixtures — realistic, mocked source payloads and record builders.

Tests must not touch the network (rule §42); these fixtures provide canned
source payloads in each source's native shape plus convenience builders for
:class:`CVERecord`s, covering the cases rule §43 asks for: critical/high/medium/
low, missing CVSS/CWE/CPE, multiple references, KEV, duplicate-across-sources,
updated CVSS, and a malformed payload.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models import (
    CVERecord, SourceRecord, AffectedProduct, KEVInfo,
)
from ..enrichment import cvss as _cvss, enrich as _enrich
from ..enrichment.cwe import make_weakness
from ..enrichment.references import classify_references
from ..utils import now_epoch


# ---------------- NVD payloads (API 2.0 shape) ----------------

def nvd_vuln(cve_id: str = "CVE-2026-93740", *, score: float = 9.8,
             vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             severity: str = "CRITICAL", cwe: str = "CWE-121",
             with_cpe: bool = True, with_refs: bool = True) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {}
    if vector or score is not None:
        metrics = {"cvssMetricV31": [{
            "cvssData": {"version": "3.1", "vectorString": vector,
                         "baseScore": score, "baseSeverity": severity},
            "exploitabilityScore": 3.9, "impactScore": 5.9,
        }]}
    weaknesses = []
    if cwe:
        weaknesses = [{"description": [{"lang": "en", "value": cwe}]}]
    configurations = []
    if with_cpe:
        configurations = [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:o:totolink:a3002mu_firmware:1.1.0:*:*:*:*:*:*:*",
        }]}]}]
    references = []
    if with_refs:
        references = [
            {"url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
             "tags": ["Third Party Advisory"]},
            {"url": "https://github.com/example/poc", "tags": ["Exploit"]},
            {"url": "https://vendor.example.com/advisory/1",
             "tags": ["Vendor Advisory"]},
        ]
    return {"cve": {
        "id": cve_id,
        "published": "2026-09-18T14:03:12.000",
        "lastModified": "2026-09-19T10:00:00.000",
        "descriptions": [{"lang": "en", "value":
            "A buffer overflow in the formWlEncrypt function in /boafrm/formWlEncrypt "
            "of Totolink A3002MU via the submit-url parameter allows remote attackers "
            "to cause a stack-based buffer overflow."}],
        "metrics": metrics,
        "weaknesses": weaknesses,
        "configurations": configurations,
        "references": references,
    }}


def nvd_response(*vulns) -> Dict[str, Any]:
    items = list(vulns) or [nvd_vuln()]
    return {"resultsPerPage": len(items), "startIndex": 0,
            "totalResults": len(items), "vulnerabilities": items}


def nvd_malformed() -> Dict[str, Any]:
    # missing 'cve' key entirely on one item, valid on another
    return {"totalResults": 2, "vulnerabilities": [
        {"notcve": {}},
        nvd_vuln("CVE-2026-00042", score=5.4, severity="MEDIUM",
                 vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"),
    ]}


# ---------------- CISA KEV ----------------

def kev_entry(cve_id: str = "CVE-2026-93740", *, ransomware: str = "Unknown") -> Dict[str, Any]:
    return {
        "cveID": cve_id,
        "vendorProject": "TOTOLINK",
        "product": "A3002MU",
        "vulnerabilityName": "TOTOLINK A3002MU Buffer Overflow Vulnerability",
        "dateAdded": "2026-09-20",
        "shortDescription": "…",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": "2026-10-11",
        "knownRansomwareCampaignUse": ransomware,
        "notes": "",
    }


def kev_catalog(*entries) -> Dict[str, Any]:
    items = list(entries) or [kev_entry()]
    return {"title": "CISA KEV", "catalogVersion": "2026.09.20",
            "count": len(items), "vulnerabilities": items}


# ---------------- GitHub advisory ----------------

def ghsa_advisory(cve_id: str = "CVE-2026-93740",
                  ghsa: str = "GHSA-2345-6789-cfgh") -> Dict[str, Any]:
    return {
        "ghsa_id": "GHSA-2345-6789-cfgh",
        "cve_id": cve_id,
        "summary": "Buffer overflow in Totolink A3002MU",
        "description": "A stack buffer overflow allows remote code execution.",
        "severity": "critical",
        "published_at": "2026-09-18T14:03:12Z",
        "updated_at": "2026-09-19T10:00:00Z",
        "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 "score": 9.8},
        "cwes": [{"cwe_id": "CWE-121", "name": "Stack-based Buffer Overflow"}],
        "vulnerabilities": [{
            "package": {"ecosystem": "npm", "name": "example-pkg"},
            "vulnerable_version_range": ">= 1.0.0, < 1.2.3",
            "first_patched_version": {"identifier": "1.2.3"},
        }],
        "references": ["https://github.com/example/advisory",
                       "https://nvd.nist.gov/vuln/detail/" + cve_id],
        "html_url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
    }


# ---------------- CVE.org 5.x ----------------

def cve_org_record(cve_id: str = "CVE-2026-93740") -> Dict[str, Any]:
    return {
        "cveMetadata": {"cveId": cve_id, "datePublished": "2026-09-18T14:03:12.000Z",
                        "dateUpdated": "2026-09-19T10:00:00.000Z"},
        "containers": {"cna": {
            "title": "Totolink A3002MU formWlEncrypt Buffer Overflow",
            "descriptions": [{"lang": "en", "value":
                "A buffer overflow in formWlEncrypt via submit-url."}],
            "metrics": [{"cvssV3_1": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.1, "baseSeverity": "CRITICAL"}}],
            "problemTypes": [{"descriptions": [
                {"cweId": "CWE-121", "description": "Stack-based Buffer Overflow"}]}],
            "affected": [{"vendor": "TOTOLINK", "product": "A3002MU",
                          "versions": [{"version": "1.1.0", "status": "affected"}]}],
            "references": [{"url": "https://www.cve.org/CVERecord?id=" + cve_id}],
        }},
    }


# ---------------- record builders ----------------

def record(cve_id: str = "CVE-2026-93740", *, score: float = 9.8,
           vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
           cwe: str = "CWE-121", vendor: str = "TOTOLINK", product: str = "A3002MU",
           kev: bool = False, source: str = "nvd", enrich_it: bool = True,
           refs=None) -> CVERecord:
    r = CVERecord(cve_id=cve_id, title=f"{vendor} {product} Buffer Overflow",
                  description="A buffer overflow allows remote attackers to execute code.",
                  published_at=now_epoch() - 86400)
    if vector:
        r.cvss_scores = [_cvss.parse_vector(vector, source=source, provided_score=score)]
    if cwe:
        w = make_weakness(cwe, source=source)
        if w:
            r.weaknesses = [w]
    if vendor or product:
        r.products = [AffectedProduct(vendor=vendor, product=product,
                                      versions_affected=["1.1.0"], source=source)]
    if refs is None:
        refs = [{"url": "https://github.com/example/poc", "tags": ["Exploit"]}]
    r.references = classify_references(refs, source=source)
    if kev:
        r.kev = KEVInfo(in_kev=True, date_added=now_epoch() - 43200,
                        required_action="Apply updates")
    r.sources = [SourceRecord(source=source, source_id=cve_id,
                              source_url="https://nvd.nist.gov/vuln/detail/" + cve_id)]
    if enrich_it:
        _enrich(r)
    return r


def record_no_cvss(cve_id: str = "CVE-2026-00001") -> CVERecord:
    return record(cve_id, score=None, vector="", cwe="", refs=[], enrich_it=True)


def record_high(cve_id: str = "CVE-2026-00002") -> CVERecord:
    return record(cve_id, score=7.5,
                  vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")


def record_medium(cve_id: str = "CVE-2026-00003") -> CVERecord:
    return record(cve_id, score=5.4,
                  vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N")


def record_low(cve_id: str = "CVE-2026-00004") -> CVERecord:
    return record(cve_id, score=3.1,
                  vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")


# ---------------- the explicit §43 fixture set ----------------

def record_critical(cve_id: str = "CVE-2026-00010") -> CVERecord:
    return record(cve_id, score=9.8,
                  vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def record_kev(cve_id: str = "CVE-2026-00011") -> CVERecord:
    return record(cve_id, kev=True)


def record_no_cwe(cve_id: str = "CVE-2026-00012") -> CVERecord:
    return record(cve_id, cwe="")


def record_no_cpe(cve_id: str = "CVE-2026-00013") -> CVERecord:
    return record(cve_id, vendor="", product="")


def record_multi_ref(cve_id: str = "CVE-2026-00014") -> CVERecord:
    return record(cve_id, refs=[
        {"url": "https://nvd.nist.gov/vuln/detail/" + cve_id, "tags": ["Third Party Advisory"]},
        {"url": "https://msrc.microsoft.com/advisory/1", "tags": ["Vendor Advisory"]},
        {"url": "https://github.com/x/poc", "tags": ["Exploit"]},
        {"url": "https://www.exploit-db.com/exploits/50000"},
        {"url": "https://seclists.org/fulldisclosure/2026/x"},
    ])


def record_updated_cvss(cve_id: str = "CVE-2026-00015"):
    """A (before, after) pair simulating a CVSS re-score for change-detection
    tests."""
    old = record(cve_id, score=7.5,
                 vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    new = record(cve_id, score=9.8, kev=True,
                 vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    return old, new


def records_duplicate_sources(cve_id: str = "CVE-2026-00016"):
    """The SAME CVE seen via three sources — for de-duplication tests."""
    nvd = record(cve_id, source="nvd")
    kev = record(cve_id, source="cisa_kev", kev=True, vector="", score=None,
                 cwe="", refs=[])
    cve_org = record(cve_id, source="cve_org", score=9.1,
                     vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                     refs=[{"url": "https://www.cve.org/CVERecord?id=" + cve_id}])
    return [nvd, kev, cve_org]
