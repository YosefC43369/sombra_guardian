"""
web_footprint.analysis.subdomain_roles — classify a subdomain by its NAME.

A subdomain's leading labels often hint at its role: ``api.``, ``dev.``,
``staging.``, ``admin.``, ``vpn.``. Surfacing that hint helps an authorized
red-teamer prioritise where to look — but it is only a *naming signal* (spec §6).

Read this carefully: a name such as ``admin.example.com`` tells you the operator
named a host "admin". It does NOT tell you an administrative interface is
exposed, reachable, or unauthenticated. This module therefore returns a role
*label* and never a claim about exposure or reachability. The pipeline records
the label on the asset; any statement that a service is actually exposed must
come from a separate, evidence-backed observation, never from the name alone.

Pure functions, standard library only.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .. import normalize

# label -> canonical role. Multiple labels can map to one role.
_ROLE_MAP: Dict[str, str] = {
    "www": "web", "web": "web", "web1": "web", "web2": "web",
    "api": "api", "apis": "api", "rest": "api", "graphql": "api", "gql": "api",
    "gateway": "api", "gw": "api",
    "dev": "development", "develop": "development", "sandbox": "development",
    "test": "testing", "testing": "testing", "qa": "testing", "uat": "testing",
    "stage": "staging", "staging": "staging", "stg": "staging", "preprod": "staging",
    "docs": "documentation", "doc": "documentation", "developer": "documentation",
    "developers": "documentation", "apidocs": "documentation", "swagger": "documentation",
    "blog": "blog", "news": "blog", "press": "blog",
    "mail": "mail", "smtp": "mail", "imap": "mail", "pop": "mail", "mx": "mail",
    "webmail": "mail", "email": "mail", "mx1": "mail", "mx2": "mail",
    "vpn": "vpn", "gw-vpn": "vpn", "sslvpn": "vpn", "remote": "vpn",
    "portal": "portal", "my": "portal", "account": "portal", "accounts": "portal",
    "login": "auth", "sso": "auth", "auth": "auth", "id": "auth", "idp": "auth",
    "oauth": "auth", "identity": "auth",
    "admin": "admin", "administrator": "admin", "manage": "admin", "manager": "admin",
    "console": "admin", "panel": "admin", "cpanel": "admin", "dashboard": "admin",
    "status": "status", "health": "status", "uptime": "status", "stats": "status",
    "cdn": "cdn", "static": "cdn", "assets": "cdn", "media": "cdn", "img": "cdn",
    "images": "cdn", "files": "cdn", "download": "cdn", "downloads": "cdn",
    "support": "support", "help": "support", "helpdesk": "support", "kb": "support",
    "ticket": "support", "tickets": "support", "service": "support",
    "git": "vcs", "gitlab": "vcs", "github": "vcs", "repo": "vcs", "code": "vcs",
    "svn": "vcs", "bitbucket": "vcs",
    "ci": "cicd", "cd": "cicd", "jenkins": "cicd", "build": "cicd", "deploy": "cicd",
    "drone": "cicd", "runner": "cicd", "pipeline": "cicd",
    "db": "database", "database": "database", "sql": "database", "mysql": "database",
    "postgres": "database", "mongo": "database", "redis": "database",
    "vault": "secrets", "secrets": "secrets", "kms": "secrets",
    "monitor": "monitoring", "monitoring": "monitoring", "grafana": "monitoring",
    "prometheus": "monitoring", "kibana": "monitoring", "metrics": "monitoring",
    "logs": "monitoring", "log": "monitoring", "elk": "monitoring",
    "shop": "commerce", "store": "commerce", "checkout": "commerce", "pay": "commerce",
    "payment": "commerce", "payments": "commerce", "billing": "commerce",
    "app": "application", "apps": "application", "mobile": "application", "m": "application",
}

# Roles that, when named, are worth flagging for attention during an authorized
# assessment (sensitive-by-name). This drives prioritisation, NOT an exposure
# claim.
_SENSITIVE_ROLES = frozenset({
    "admin", "auth", "vpn", "database", "secrets", "cicd", "staging",
    "development", "testing", "monitoring",
})


def classify_label(label: str) -> Optional[str]:
    """Map a single DNS label to a role, or None if unrecognised."""
    lbl = (label or "").strip().lower()
    if lbl in _ROLE_MAP:
        return _ROLE_MAP[lbl]
    # Numbered variants like api-2, web01, staging-eu.
    stripped = lbl.rstrip("0123456789")
    for sep in ("-", "_"):
        head = stripped.split(sep, 1)[0]
        if head in _ROLE_MAP:
            return _ROLE_MAP[head]
    if stripped and stripped in _ROLE_MAP:
        return _ROLE_MAP[stripped]
    return None


def classify_host(host: str) -> Dict[str, object]:
    """Return {role, matched_label, sensitive, labels} for a hostname.

    ``role`` is the first recognised role among the leading labels (most-specific
    first), or "" if none matched. ``sensitive`` marks a sensitive-by-name role
    for prioritisation only."""
    labels, base = normalize.split_host_labels(host)
    role = ""
    matched = ""
    for lbl in labels:  # left-to-right: api.dev.example.com → 'api' wins
        r = classify_label(lbl)
        if r:
            role, matched = r, lbl
            break
    return {
        "role": role,
        "matched_label": matched,
        "sensitive": role in _SENSITIVE_ROLES,
        "labels": labels,
        "base_domain": base or "",
    }


def is_sensitive_role(role: str) -> bool:
    return (role or "").strip().lower() in _SENSITIVE_ROLES
