"""
cve_tracker.constants — fixed, non-configurable facts and compiled patterns.

Anything an operator might want to tune lives in :mod:`cve_tracker.config` and
is read from the environment. What lives *here* is structural: the shape of a
CVE id, the canonical API endpoints, the reference-domain allowlist used by the
classifier, and the emoji/label vocabulary the Thai formatter draws from.

Nothing in this module reads the environment or performs I/O, so it is safe to
import from anywhere (including migrations and tests) with no side effects.
"""

from __future__ import annotations

import re

# ---------------- Identity patterns ----------------

# A CVE identifier: CVE-YYYY-NNNN.. (4+ digits, year 1999..2099). Anchored
# forms for validation; unanchored for extraction from free text.
CVE_ID_RE = re.compile(r"^CVE-(?P<year>(?:1999|2\d{3}|20\d{2}))-(?P<seq>\d{4,19})$", re.I)
CVE_ID_SCAN_RE = re.compile(r"\bCVE-(?:1999|2\d{3}|20\d{2})-\d{4,19}\b", re.I)

# GitHub Security Advisory id: GHSA-xxxx-xxxx-xxxx (base32-ish, 4-4-4 groups).
GHSA_ID_RE = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$", re.I)
GHSA_ID_SCAN_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)

# CWE identifier: CWE-79 etc.
CWE_ID_RE = re.compile(r"^CWE-(?P<num>\d{1,6})$", re.I)
CWE_ID_SCAN_RE = re.compile(r"\bCWE-\d{1,6}\b", re.I)

# CPE 2.3 URI binding: cpe:2.3:part:vendor:product:version:...
CPE23_RE = re.compile(
    r"^cpe:2\.3:(?P<part>[aho*\-]):(?P<vendor>[^:]*):(?P<product>[^:]*):"
    r"(?P<version>[^:]*):(?P<update>[^:]*):(?P<edition>[^:]*):(?P<language>[^:]*):"
    r"(?P<sw_edition>[^:]*):(?P<target_sw>[^:]*):(?P<target_hw>[^:]*):(?P<other>[^:]*)$",
    re.I,
)
# CPE 2.2 legacy URI binding: cpe:/a:vendor:product:version
CPE22_RE = re.compile(
    r"^cpe:/(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*)(?::(?P<version>[^:]*))?",
    re.I,
)

# CVSS vector prefixes.
CVSS3_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/", re.I)
CVSS4_VECTOR_RE = re.compile(r"^CVSS:4\.0/", re.I)
# CVSS v2 has no prefix; it is a bare AV:.../AC:.../Au:... string.
CVSS2_VECTOR_RE = re.compile(r"^(AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC])", re.I)


# ---------------- Canonical source endpoints ----------------
# These are the documented, ToS-friendly JSON APIs / feeds. They are defaults;
# config.py lets an operator override each base URL (e.g. to point NVD at a
# mirror) without touching code.

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_API = "https://cveawg.mitre.org/api/cve"
CVE_ORG_RECENT = "https://cveawg.mitre.org/api/cve"  # filtered via query params
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
GITHUB_GRAPHQL = "https://api.github.com/graphql"

# Public reference lookups used only to CLASSIFY a reference URL (domain
# matching); the subsystem never fetches these.
EXPLOIT_DB_HOSTS = frozenset({"exploit-db.com", "www.exploit-db.com"})
POC_HINT_HOSTS = frozenset({
    "github.com", "gitlab.com", "packetstormsecurity.com",
    "raw.githubusercontent.com", "gist.github.com",
})

# Domains recognised as vendor advisories (extend freely — the classifier
# degrades to VENDOR_ADVISORY on a keyword match too).
VENDOR_ADVISORY_HOSTS = frozenset({
    "msrc.microsoft.com", "microsoft.com", "portal.msrc.microsoft.com",
    "security.apple.com", "support.apple.com",
    "sec.cloudapps.cisco.com", "tools.cisco.com", "cisco.com",
    "access.redhat.com", "redhat.com",
    "ubuntu.com", "usn.ubuntu.com",
    "security.gentoo.org", "lists.debian.org", "debian.org",
    "oracle.com", "www.oracle.com",
    "adobe.com", "helpx.adobe.com",
    "fortiguard.com", "fortinet.com",
    "paloaltonetworks.com", "security.paloaltonetworks.com",
    "vmware.com", "spring.io",
    "apache.org", "lists.apache.org",
    "gitlab.com", "atlassian.com", "confluence.atlassian.com",
    "jenkins.io", "kb.cert.org", "cert.org",
    "chromereleases.googleblog.com", "android.com", "source.android.com",
    "wordpress.org", "wpscan.com",
})

PATCH_HINT_KEYWORDS = (
    "patch", "commit", "/pull/", "/commit/", "fixed", "fix-", "security-fix",
    "hotfix", "update", "release-notes", "changelog",
)
ADVISORY_HINT_KEYWORDS = ("advisory", "advisories", "bulletin", "vuln", "vulnerability", "sa-", "cve-")
EXPLOIT_HINT_KEYWORDS = ("exploit", "poc", "proof-of-concept", "proof_of_concept", "0day", "rce-poc")
RESEARCH_HINT_KEYWORDS = ("research", "whitepaper", "analysis", "writeup", "write-up", "blog", "labs")
MAILING_LIST_HINT_KEYWORDS = ("seclists", "openwall", "bugtraq", "full-disclosure", "mailman", "listinfo")


# ---------------- Limits (structural safety ceilings) ----------------
# These are hard caps the code enforces regardless of config, to bound memory
# and message size. Config values must stay at or under these.

ABSOLUTE_MAX_RESPONSE_BYTES = 64 * 1024 * 1024   # 64 MiB — hard fetch ceiling
TELEGRAM_HARD_LIMIT = 4096                        # Telegram per-message cap
TELEGRAM_CAPTION_LIMIT = 1024                     # photo caption cap
MAX_DESCRIPTION_STORE = 20000                     # truncate stored descriptions
MAX_REFERENCES_STORE = 200                        # per CVE
MAX_PRODUCTS_STORE = 500                          # per CVE
MAX_AI_SUMMARY_CHARS = 3500                       # leave headroom under 4096
MAX_CVE_ID_LEN = 30


# ---------------- Thai formatter vocabulary ----------------
# Centralised so templates, dispatcher and validator agree on the same emoji.

EMOJI = {
    "new": "🚨",
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "none": "⚪",
    "unknown": "❔",
    "kev": "🔥",
    "id": "🆔",
    "published": "📅",
    "severity": "🚨",
    "cwe": "🏷️",
    "vendor": "🏢",
    "product": "📦",
    "summary": "📝",
    "impact": "⚠️",
    "vector": "🌐",
    "privileges": "🔐",
    "user_interaction": "👤",
    "exploit": "🧪",
    "recommendation": "🛠️",
    "references": "🔗",
    "ai": "🤖",
    "updated": "🔄",
    "timeline": "🗓️",
    "priority": "🎯",
    "healthy": "🟢",
    "degraded": "🟡",
    "failing": "🔴",
    "disabled": "⚫",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "NONE": "⚪",
    "UNKNOWN": "❔",
}

# Thai month names for human-friendly date rendering (พ.ศ. handled in utils).
THAI_MONTHS = [
    "", "มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน", "พฤษภาคม", "มิถุนายน",
    "กรกฎาคม", "สิงหาคม", "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม",
]
THAI_MONTHS_SHORT = [
    "", "ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.",
    "ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค.",
]

# Static user-facing strings the AI must reuse verbatim when a fact is absent,
# so "unknown" reads consistently across AI output and deterministic fallback.
TH_UNKNOWN = "ไม่พบข้อมูล"
TH_UNCONFIRMED = "ยังไม่มีข้อมูลยืนยันจากแหล่งข้อมูลที่ตรวจสอบ"
TH_NOT_APPLICABLE = "ไม่ระบุ"

# Per-source default trust weight used when two sources disagree on a scalar
# (e.g. CVSS). Higher wins the *display* slot; both values are always stored.
SOURCE_TRUST = {
    "nvd": 90,
    "cisa_kev": 95,       # authoritative for exploited-in-the-wild only
    "cve_org": 80,
    "github_advisory": 70,
    "vendor_advisory": 85,
    "other": 40,
}
