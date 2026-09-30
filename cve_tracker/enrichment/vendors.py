"""
cve_tracker.enrichment.vendors — vendor-name normalization and aliasing.

Sources spell the same vendor many ways ('Microsoft', 'microsoft',
'Microsoft Corporation', 'msft'). A canonical vendor name makes correlation
queries ('CVEs related to Microsoft') and subscription filters reliable without
a heavyweight CMDB. The alias table is small and additive — unknown vendors are
title-cased and passed through, never dropped.
"""

from __future__ import annotations

from typing import Dict, List

from ..utils import slugify, dedupe_preserve_order

# slug -> canonical display name. Extend freely; this only affects grouping and
# display, never storage of the original per-source value.
_VENDOR_ALIASES: Dict[str, str] = {
    "microsoft": "Microsoft",
    "microsoft-corporation": "Microsoft",
    "msft": "Microsoft",
    "apple": "Apple",
    "apple-inc": "Apple",
    "google": "Google",
    "google-llc": "Google",
    "cisco": "Cisco",
    "cisco-systems": "Cisco",
    "oracle": "Oracle",
    "oracle-corporation": "Oracle",
    "redhat": "Red Hat",
    "red-hat": "Red Hat",
    "adobe": "Adobe",
    "adobe-inc": "Adobe",
    "vmware": "VMware",
    "fortinet": "Fortinet",
    "paloaltonetworks": "Palo Alto Networks",
    "palo-alto-networks": "Palo Alto Networks",
    "atlassian": "Atlassian",
    "apache": "Apache Software Foundation",
    "apache-software-foundation": "Apache Software Foundation",
    "the-apache-software-foundation": "Apache Software Foundation",
    "linux": "Linux",
    "linux-kernel": "Linux",
    "canonical": "Canonical",
    "debian": "Debian",
    "gitlab": "GitLab",
    "github": "GitHub",
    "jenkins": "Jenkins",
    "wordpress": "WordPress",
    "ibm": "IBM",
    "sap": "SAP",
    "siemens": "Siemens",
    "schneider-electric": "Schneider Electric",
    "totolink": "TOTOLINK",
    "dlink": "D-Link",
    "d-link": "D-Link",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "netgear": "NETGEAR",
    "zyxel": "Zyxel",
    "juniper": "Juniper Networks",
    "juniper-networks": "Juniper Networks",
    "f5": "F5 Networks",
    "f5-networks": "F5 Networks",
    "citrix": "Citrix",
    "sonicwall": "SonicWall",
    "sophos": "Sophos",
    "trendmicro": "Trend Micro",
    "trend-micro": "Trend Micro",
    "mcafee": "McAfee",
    "symantec": "Symantec",
    "broadcom": "Broadcom",
    "qnap": "QNAP",
    "synology": "Synology",
    "mikrotik": "MikroTik",
    "huawei": "Huawei",
    "lenovo": "Lenovo",
    "dell": "Dell",
    "hp": "HP",
    "hewlett-packard": "HP",
    "hpe": "Hewlett Packard Enterprise",
    "intel": "Intel",
    "amd": "AMD",
    "nvidia": "NVIDIA",
    "qualcomm": "Qualcomm",
    "mozilla": "Mozilla",
    "nodejs": "Node.js",
    "node-js": "Node.js",
    "python": "Python Software Foundation",
    "django": "Django Software Foundation",
    "php": "PHP Group",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "mongodb": "MongoDB",
    "elastic": "Elastic",
    "elasticsearch": "Elastic",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "hashicorp": "HashiCorp",
    "grafana": "Grafana Labs",
    "nginx": "NGINX",
    "openssl": "OpenSSL",
    "openssh": "OpenSSH",
    "samba": "Samba",
    "curl": "curl",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "magento": "Magento",
    "moodle": "Moodle",
    "jetbrains": "JetBrains",
    "progress": "Progress Software",
    "moveit": "Progress Software",
    "ivanti": "Ivanti",
    "zoom": "Zoom",
    "slack": "Slack",
    "salesforce": "Salesforce",
    "servicenow": "ServiceNow",
}


def canonical_vendor(name: str) -> str:
    """Return the canonical display name for a vendor, or a title-cased
    passthrough for unknown vendors."""
    if not name:
        return ""
    slug = slugify(name)
    if slug in _VENDOR_ALIASES:
        return _VENDOR_ALIASES[slug]
    # Passthrough: preserve the source string but trimmed.
    return name.strip()


def vendor_key(name: str) -> str:
    """Stable matching key: canonical name slugified. Used by filters and
    correlation so 'microsoft' matches 'Microsoft Corporation'."""
    return slugify(canonical_vendor(name))


def match_vendor(candidate: str, wanted: List[str]) -> bool:
    """True if ``candidate`` matches any wanted vendor (by canonical key, or a
    substring of the slug for partial filters like 'micro')."""
    if not candidate or not wanted:
        return False
    ck = vendor_key(candidate)
    cslug = slugify(candidate)
    for w in wanted:
        wk = vendor_key(w)
        wslug = slugify(w)
        if not wk:
            continue
        if ck == wk or wslug in cslug or wslug in ck:
            return True
    return False


def normalize_vendor_list(names: List[str]) -> List[str]:
    return dedupe_preserve_order([canonical_vendor(n) for n in names if n])
