"""
osint.sources.site_tech — passive web technology & security-header fingerprint.

WHAT / WHY. Fetching a site's home page over HTTPS and reading what it already
sends back — response headers, cookie flags, the ``generator`` meta tag, script
sources — is a passive way to enumerate the tech stack (server, framework, CMS
and versions) and to see which HTTP security headers are present or missing.
That is exactly the input a defender uses to reason about exposure: an outdated,
publicly-versioned CMS or a missing HSTS/CSP is a documented risk signal. This
module does one GET of ``https://<domain>/`` (following redirects, handled by
async_http) and one of ``/robots.txt``; it never logs in, never fuzzes paths,
never sends a crafted request. It only reads what the server volunteers.

Output is structured so ``osint.risk`` can score it: a ``tech`` record per
detected product (with version when disclosed), a ``security_header`` record
per expected header (present/​missing), and a compact ``meta`` block.
"""

import re
import logging
from typing import Any, Dict, List, Optional, Tuple

from .base import Source, SourceResult, SourceStatus
from ..utils import validators

logger = logging.getLogger("modbot.osint.site_tech")

# HTTP security headers we expect a well-configured site to set, with the
# short label used in the risk model.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# Headers that leak stack/version information (their presence is itself a note).
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                      "x-aspnetmvc-version", "x-generator", "via")

_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_VER_IN_PATH_RE = re.compile(r'([a-zA-Z][\w.\-]*?)[-/](\d+\.\d+(?:\.\d+)?)')

# Signatures: substring in URL/header/html -> product name.
_LIB_SIGNS = (
    ("jquery", "jQuery"),
    ("bootstrap", "Bootstrap"),
    ("react", "React"),
    ("vue", "Vue.js"),
    ("angular", "Angular"),
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("/sites/default/", "Drupal"),
    ("/media/jui/", "Joomla"),
)


class SiteTechSource(Source):
    name = "site_tech"
    kind = "domain"
    requires_key = False

    async def fetch(self, client, target: str) -> SourceResult:
        domain = validators.normalize_domain(target)
        if domain is None:
            return self._invalid(target, "not a valid domain")

        url = f"https://{domain}/"
        result = await client.get(url)
        if not result.ok and result.status == 0:
            # HTTPS transport failed entirely — try plain HTTP once so we can at
            # least report "no TLS / redirects to HTTPS?" (a real risk signal).
            result = await client.get(f"http://{domain}/")
            if not result.ok and result.status == 0:
                return self._error(domain, result.reason or "site unreachable")

        headers = {k.lower(): v for k, v in (result.headers or {}).items()}
        html = result.text or ""
        final_url = result.url or url
        https_ok = str(final_url).lower().startswith("https://")

        records: List[Dict[str, Any]] = []
        meta: Dict[str, Any] = {
            "final_url": final_url,
            "status": result.status,
            "https": https_ok,
        }

        # (1) disclosure headers -> tech records
        tech_products: Dict[str, Optional[str]] = {}
        for h in DISCLOSURE_HEADERS:
            if h in headers:
                value = headers[h].strip()
                meta.setdefault("disclosure", {})[h] = value
                for product, version in self._products_from_value(value):
                    tech_products.setdefault(product, version)

        # (2) generator meta + script srcs from HTML
        m = _META_GENERATOR_RE.search(html)
        if m:
            for product, version in self._products_from_value(m.group(1)):
                tech_products[product] = version or tech_products.get(product)
        for src in _SCRIPT_SRC_RE.findall(html)[:60]:
            for product, version in self._products_from_src(src):
                tech_products.setdefault(product, version)
        for needle, product in _LIB_SIGNS:
            if needle in html.lower():
                tech_products.setdefault(product, None)

        for product, version in sorted(tech_products.items()):
            value = f"{product} {version}".strip() if version else product
            records.append({"type": "tech", "value": value, "product": product,
                            "version": version, "source": self.name})

        # (3) security headers present/missing
        present, missing = [], []
        for header_key, label in SECURITY_HEADERS.items():
            if header_key in headers:
                present.append(label)
                records.append({"type": "security_header", "value": label,
                                "present": True, "source": self.name})
            else:
                missing.append(label)
                records.append({"type": "security_header", "value": label,
                                "present": False, "source": self.name})
        meta["security_headers_present"] = present
        meta["security_headers_missing"] = missing

        # (4) cookie flags (best-effort — merged Set-Cookie may hide duplicates)
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            meta["cookie_secure"] = "secure" in set_cookie.lower()
            meta["cookie_httponly"] = "httponly" in set_cookie.lower()

        # (5) robots.txt (advertises admin/hidden paths; passive read only)
        robots = await client.get(f"https://{domain}/robots.txt")
        if robots.ok and robots.text:
            disallow = re.findall(r'(?im)^\s*Disallow:\s*(\S+)', robots.text)
            if disallow:
                meta["robots_disallow"] = sorted(set(disallow))[:40]

        return SourceResult(self.name, domain, SourceStatus.OK, records=records,
                            meta=meta)

    @staticmethod
    def _products_from_value(value: str) -> List[Tuple[str, Optional[str]]]:
        """แยกชื่อผลิตภัณฑ์+เวอร์ชันจากค่า header/generator เช่น
        'Apache/2.4.29 (Ubuntu)' -> [('Apache','2.4.29'), ('Ubuntu', None)]"""
        out: List[Tuple[str, Optional[str]]] = []
        for token in re.split(r'[\s,()]+', value):
            token = token.strip()
            if not token:
                continue
            if "/" in token:
                name, _, ver = token.partition("/")
                out.append((name.strip(), ver.strip() or None))
            elif re.match(r'^\d+\.\d', token) and out:
                # version that trails the previous bare name
                last_name, last_ver = out[-1]
                if last_ver is None:
                    out[-1] = (last_name, token)
            else:
                out.append((token, None))
        return [(n, v) for n, v in out if n]

    @staticmethod
    def _products_from_src(src: str) -> List[Tuple[str, Optional[str]]]:
        out: List[Tuple[str, Optional[str]]] = []
        low = src.lower()
        for needle, product in _LIB_SIGNS:
            if needle in low:
                m = _VER_IN_PATH_RE.search(src)
                out.append((product, m.group(2) if m else None))
        return out


async def fetch_site_tech(client, domain: str) -> SourceResult:
    return await SiteTechSource().run(client, domain)
