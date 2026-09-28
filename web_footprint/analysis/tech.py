"""
web_footprint.analysis.tech — passive web-technology fingerprinting.

Given only what a normal public page retrieval already returned — the response
headers, cookies and HTML body — this module infers the technologies a site
publicly advertises: CMS, frontend/backend frameworks, JS libraries, CDN,
hosting, analytics, auth/payment/SaaS platforms, monitoring and CI/CD references,
and static-site generators (spec §8). Where a version string is publicly visible
(a ``Server:`` banner, an ``X-Powered-By`` header, a ``<meta name=generator>``
tag, a versioned script filename) it is recorded with its source (spec §9).

Two disciplines, both from the spec:
  * It only *reads* indicators the server already exposes. It does not exploit,
    probe, or fingerprint by behaviour — it is pure analysis of bytes already
    fetched.
  * A detected version is recorded as an observation, never turned into a
    vulnerability claim (spec §9). Vulnerability enrichment, if any, is a
    separate, opt-in step handled elsewhere.

Pure functions, standard library only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# --- signature tables ------------------------------------------------------ #
# Each entry: (name, category, compiled-pattern). Header patterns match against
# a "Header: value" line; body patterns against the HTML; cookie patterns
# against a cookie name.

_VERSION = r"([0-9]+(?:\.[0-9]+){0,3})"

_HEADER_SIGS: List[Tuple[str, str, "re.Pattern"]] = [
    ("nginx", "web-server", re.compile(r"server:\s*nginx(?:/" + _VERSION + r")?", re.I)),
    ("Apache", "web-server", re.compile(r"server:\s*apache(?:/" + _VERSION + r")?", re.I)),
    ("Microsoft-IIS", "web-server", re.compile(r"server:\s*microsoft-iis(?:/" + _VERSION + r")?", re.I)),
    ("LiteSpeed", "web-server", re.compile(r"server:\s*litespeed", re.I)),
    ("PHP", "language", re.compile(r"x-powered-by:\s*php(?:/" + _VERSION + r")?", re.I)),
    ("ASP.NET", "framework", re.compile(r"x-powered-by:\s*asp\.net", re.I)),
    ("ASP.NET", "framework", re.compile(r"x-aspnet-version:\s*" + _VERSION, re.I)),
    ("Express", "framework", re.compile(r"x-powered-by:\s*express", re.I)),
    ("Cloudflare", "cdn", re.compile(r"server:\s*cloudflare", re.I)),
    ("Cloudflare", "cdn", re.compile(r"cf-ray:", re.I)),
    ("Fastly", "cdn", re.compile(r"(x-served-by:\s*cache|x-fastly|via:\s*[^\n]*varnish)", re.I)),
    ("Amazon CloudFront", "cdn", re.compile(r"(via:\s*[^\n]*cloudfront|x-amz-cf-id:)", re.I)),
    ("Akamai", "cdn", re.compile(r"(x-akamai|akamaighost)", re.I)),
    ("Vercel", "hosting", re.compile(r"(server:\s*vercel|x-vercel-id:)", re.I)),
    ("Netlify", "hosting", re.compile(r"(server:\s*netlify|x-nf-request-id:)", re.I)),
    ("GitHub Pages", "hosting", re.compile(r"server:\s*github\.com", re.I)),
    ("Amazon S3", "hosting", re.compile(r"server:\s*amazons3", re.I)),
    ("Google Frontend", "hosting", re.compile(r"server:\s*(gfe|google frontend)", re.I)),
    ("Varnish", "cache", re.compile(r"(x-varnish:|via:\s*[^\n]*varnish)", re.I)),
    ("WordPress", "cms", re.compile(r"x-powered-by:\s*w3\s*total\s*cache", re.I)),
]

_COOKIE_SIGS: List[Tuple[str, str, "re.Pattern"]] = [
    ("PHP", "language", re.compile(r"^phpsessid$", re.I)),
    ("ASP.NET", "framework", re.compile(r"^asp\.net_sessionid$", re.I)),
    ("Java", "language", re.compile(r"^jsessionid$", re.I)),
    ("Laravel", "framework", re.compile(r"^laravel_session$", re.I)),
    ("Django", "framework", re.compile(r"^(csrftoken|sessionid)$", re.I)),
    ("Rails", "framework", re.compile(r"_session_id$", re.I)),
    ("WordPress", "cms", re.compile(r"^wordpress_", re.I)),
]

_BODY_SIGS: List[Tuple[str, str, "re.Pattern"]] = [
    ("WordPress", "cms", re.compile(r"/wp-(content|includes|json)/", re.I)),
    ("Drupal", "cms", re.compile(r"(sites/(all|default)/|drupal\.js|X-Generator.*Drupal)", re.I)),
    ("Joomla", "cms", re.compile(r"/media/jui/|joomla", re.I)),
    ("Ghost", "cms", re.compile(r"content=\"ghost", re.I)),
    ("Shopify", "commerce", re.compile(r"cdn\.shopify\.com|shopify", re.I)),
    ("Magento", "commerce", re.compile(r"(/static/version|mage/|magento)", re.I)),
    ("WooCommerce", "commerce", re.compile(r"woocommerce", re.I)),
    ("React", "js-framework", re.compile(r"(data-reactroot|__reactcontainer|/react(?:\.min)?\.js)", re.I)),
    ("Next.js", "js-framework", re.compile(r"(/_next/static/|__next_data__)", re.I)),
    ("Vue.js", "js-framework", re.compile(r"(data-v-[0-9a-f]{8}|vue(?:\.min)?\.js)", re.I)),
    ("Nuxt", "js-framework", re.compile(r"(__nuxt|/_nuxt/)", re.I)),
    ("Angular", "js-framework", re.compile(r"(ng-version=|angular(?:\.min)?\.js)", re.I)),
    ("Svelte", "js-framework", re.compile(r"svelte-[0-9a-z]{6}", re.I)),
    ("jQuery", "js-library", re.compile(r"jquery[-.]" + _VERSION + r"(?:\.min)?\.js", re.I)),
    ("Bootstrap", "ui", re.compile(r"bootstrap(?:[-.]" + _VERSION + r")?(?:\.min)?\.(?:css|js)", re.I)),
    ("Tailwind CSS", "ui", re.compile(r"(tailwind|--tw-)", re.I)),
    ("Google Analytics", "analytics", re.compile(r"(google-analytics\.com/analytics\.js|gtag\(|googletagmanager\.com/gtag)", re.I)),
    ("Google Tag Manager", "analytics", re.compile(r"googletagmanager\.com/gtm\.js", re.I)),
    ("Segment", "analytics", re.compile(r"cdn\.segment\.(com|io)", re.I)),
    ("Hotjar", "analytics", re.compile(r"static\.hotjar\.com", re.I)),
    ("Matomo", "analytics", re.compile(r"(matomo\.js|piwik\.js)", re.I)),
    ("Stripe", "payment", re.compile(r"js\.stripe\.com", re.I)),
    ("PayPal", "payment", re.compile(r"(paypalobjects\.com|paypal\.com/sdk)", re.I)),
    ("Braintree", "payment", re.compile(r"braintreegateway\.com", re.I)),
    ("Auth0", "auth-platform", re.compile(r"(cdn\.auth0\.com|auth0\.js|\.auth0\.com)", re.I)),
    ("Okta", "auth-platform", re.compile(r"\.okta(?:cdn)?\.com", re.I)),
    ("Firebase", "cloud", re.compile(r"(firebaseio\.com|firebaseapp\.com|firebase\.js)", re.I)),
    ("Sentry", "monitoring", re.compile(r"(browser\.sentry-cdn\.com|sentry\.io|__sentry)", re.I)),
    ("Datadog", "monitoring", re.compile(r"datadoghq(?:-browser-agent)?\.com", re.I)),
    ("New Relic", "monitoring", re.compile(r"(js-agent\.newrelic\.com|nreum)", re.I)),
    ("Intercom", "saas", re.compile(r"(widget\.intercom\.io|intercomcdn)", re.I)),
    ("HubSpot", "saas", re.compile(r"(js\.hs-scripts\.com|hubspot)", re.I)),
    ("Zendesk", "saas", re.compile(r"(zdassets\.com|zendesk)", re.I)),
    ("Cloudflare", "cdn", re.compile(r"(cdnjs\.cloudflare\.com|/cdn-cgi/)", re.I)),
    ("Hugo", "static-site-generator", re.compile(r"content=\"hugo", re.I)),
    ("Jekyll", "static-site-generator", re.compile(r"content=\"jekyll", re.I)),
    ("Gatsby", "static-site-generator", re.compile(r"(id=\"___gatsby\"|/page-data/)", re.I)),
]

_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", re.I)
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
_SETCOOKIE_NAME_RE = re.compile(r"^\s*([^=;\s]+)=")


def _extract_version(text: str, pattern: "re.Pattern") -> Optional[str]:
    m = pattern.search(text)
    if m and m.groups():
        for g in m.groups():
            if g and re.match(r"^[0-9]", g):
                return g
    return None


def fingerprint(headers: Dict[str, str], body: str = "",
                url: str = "") -> List[Dict[str, Any]]:
    """Return a list of detected technologies. Each: {name, category, version,
    source, confidence}. De-duplicated by name (best evidence wins)."""
    headers = headers or {}
    body = body or ""
    # Build a normalized "Header: value" blob for header signatures.
    header_lines = []
    set_cookie_names: List[str] = []
    for k, v in headers.items():
        key = str(k).lower()
        val = str(v)
        header_lines.append(f"{key}: {val}")
        if key == "set-cookie":
            for cookie in re.split(r",(?=[^;]+=)", val):
                m = _SETCOOKIE_NAME_RE.match(cookie)
                if m:
                    set_cookie_names.append(m.group(1))
    header_blob = "\n".join(header_lines)

    found: Dict[str, Dict[str, Any]] = {}

    def _add(name: str, category: str, source: str, version: Optional[str],
             confidence: float) -> None:
        key = name.lower()
        cur = found.get(key)
        if cur is None:
            found[key] = {"name": name, "category": category, "source": source,
                          "version": version or "", "confidence": confidence}
        else:
            cur["confidence"] = min(1.0, cur["confidence"] + 0.15)
            if version and not cur.get("version"):
                cur["version"] = version
                cur["source"] = source

    for name, cat, pat in _HEADER_SIGS:
        if pat.search(header_blob):
            _add(name, cat, "header", _extract_version(header_blob, pat), 0.9)

    for cname in set_cookie_names:
        for name, cat, pat in _COOKIE_SIGS:
            if pat.match(cname):
                _add(name, cat, "cookie", None, 0.7)

    for name, cat, pat in _BODY_SIGS:
        if pat.search(body):
            _add(name, cat, "html", _extract_version(body, pat), 0.6)

    # <meta name="generator"> gives both a technology and often a version.
    for gen in _GENERATOR_RE.findall(body):
        gm = re.match(r"\s*([A-Za-z][\w .\-]*?)\s*" + _VERSION + r"?\s*$", gen.strip())
        if gm:
            name = gm.group(1).strip()
            ver = gm.group(2) if gm.lastindex and gm.lastindex >= 2 else None
            if name:
                _add(name, "generator", "meta-generator", ver, 0.85)

    # Versioned script filenames (e.g. jquery-3.6.0.min.js) already covered by
    # _BODY_SIGS for known libs; nothing extra needed here.
    return sorted(found.values(), key=lambda t: (t["category"], t["name"].lower()))


def technology_versions(techs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter a fingerprint result to entries that carry a version (spec §9)."""
    return [{"technology": t["name"], "version": t["version"],
             "source": t.get("source", ""), "confidence": t.get("confidence", 0.0)}
            for t in techs if t.get("version")]
