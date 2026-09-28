"""
web_footprint.analysis.security_signals — passive, observable security signals.

From data already fetched (a ``/.well-known/security.txt`` body, response
headers, page HTML), this module records the *factual* security signals an
organization publishes: a security.txt contact/policy, HTTPS security headers
(HSTS, CSP, X-Frame-Options, …), a bug-bounty / vulnerability-disclosure program,
a public security contact, and a status page (spec §31–38, §53).

It is deliberately descriptive. It does NOT perform active security testing
(spec §31), and — importantly — it does NOT roll these signals up into a
"security posture" or "maturity" score (spec §46, §53). Each signal is returned
as an observed fact so an authorized researcher can see the organization's
declared security-reporting process and public hardening indicators without the
engine passing judgement.

Pure functions, standard library only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .. import normalize

# Known bug-bounty / disclosure platform hosts -> provider label.
_BOUNTY_HOSTS = {
    "hackerone.com": "hackerone",
    "bugcrowd.com": "bugcrowd",
    "intigriti.com": "intigriti",
    "yeswehack.com": "yeswehack",
    "hackenproof.com": "hackenproof",
    "immunefi.com": "immunefi",
}
_BOUNTY_PATH_RE = re.compile(
    r"/(?:security|bug-?bounty|vulnerability-disclosure|responsible-disclosure|vdp|\.well-known/security\.txt)\b",
    re.I)

# Security-relevant response headers and how to describe them. Presence and
# value are recorded; absence of a header is reported as an observation too.
_SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("content-security-policy-report-only", "CSP-Report-Only"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "COOP"),
    ("cross-origin-embedder-policy", "COEP"),
    ("cross-origin-resource-policy", "CORP"),
]


def parse_security_txt(text: str, url: str = "") -> Dict[str, Any]:
    """Parse an RFC 9116 security.txt body into its fields (spec §32)."""
    fields: Dict[str, List[str]] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if value:
            fields.setdefault(key, []).append(value)
    return {
        "type": "security_txt",
        "value": url or "security.txt",
        "source": "wellknown",
        "contact": fields.get("contact", []),
        "policy": fields.get("policy", []),
        "acknowledgments": fields.get("acknowledgments", []),
        "encryption": fields.get("encryption", []),
        "expires": (fields.get("expires") or [""])[0],
        "canonical": fields.get("canonical", []),
        "present": bool(fields),
    }


def analyze_headers(headers: Dict[str, str], url: str = "") -> List[Dict[str, Any]]:
    """Return one record per security-relevant header (present or absent)."""
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    out: List[Dict[str, Any]] = []
    for header, label in _SECURITY_HEADERS:
        present = header in lower
        out.append({
            "type": "security_header", "value": label, "header": header,
            "present": present, "header_value": lower.get(header, "")[:300],
            "url": url, "source": "wellknown",
        })
    # HTTPS itself.
    if url:
        out.append({"type": "transport", "value": "https",
                    "present": url.lower().startswith("https://"),
                    "url": url, "source": "wellknown"})
    return out


def detect_bug_bounty(texts_and_urls: List[str]) -> List[Dict[str, Any]]:
    """Detect public bug-bounty / disclosure references in text or URLs
    (spec §33). Records the program provider and scope/policy URL where visible.

    A detected program does NOT imply authorization to test (spec §34); it is
    recorded so a researcher can find the declared reporting process and any
    published scope."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for blob in texts_and_urls:
        blob = blob or ""
        for host, provider in _BOUNTY_HOSTS.items():
            for m in re.finditer(re.escape(host) + r"/[A-Za-z0-9_\-./]*", blob, re.I):
                ref = m.group(0)
                key = (provider, ref.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append({"type": "bug_bounty", "provider": provider,
                            "value": "https://" + ref, "source": "extract",
                            "note": "public program reference; not authorization"})
        for m in _BOUNTY_PATH_RE.finditer(blob):
            ref = m.group(0)
            key = ("self-hosted", ref.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": "disclosure_policy", "provider": "self-hosted",
                        "value": ref, "source": "extract",
                        "note": "declared disclosure/security path"})
    return out


def detect_status_page(host: str, texts_and_urls: List[str]) -> List[Dict[str, Any]]:
    """Detect a public status/incident page (spec §37) from host name or refs."""
    out: List[Dict[str, Any]] = []
    seen = set()
    labels, _ = normalize.split_host_labels(host)
    if any(lbl in ("status", "uptime", "health") for lbl in labels):
        out.append({"type": "status_page", "value": host, "source": "wellknown"})
        seen.add(host)
    for blob in texts_and_urls:
        for m in re.finditer(r"\b[a-z0-9\-]+\.(?:statuspage\.io|status\.io|"
                             r"instatus\.com|betteruptime\.com)\b", blob or "", re.I):
            ref = m.group(0).lower()
            if ref not in seen:
                seen.add(ref)
                out.append({"type": "status_page", "value": ref, "source": "extract"})
    return out
