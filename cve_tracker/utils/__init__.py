"""
cve_tracker.utils — small, dependency-light helpers shared across layers.

Each module here is pure (no network, no DB) so it is trivially testable and
safe to import from anywhere in the subsystem.
"""

from .text import (
    normalize_ws,
    truncate,
    strip_html,
    escape_html,
    escape_markdown_v2,
    safe_json_loads,
    coalesce,
    dedupe_preserve_order,
    slugify,
)
from .ids import (
    normalize_cve_id,
    is_valid_cve_id,
    extract_cve_ids,
    normalize_cwe_id,
    extract_cwe_ids,
    normalize_ghsa_id,
    cve_year,
    cve_sort_key,
)
from .timeparse import (
    parse_timestamp,
    to_epoch,
    now_epoch,
    iso_utc,
    thai_date,
    thai_datetime,
    humanize_ago,
)
from .urls import (
    normalize_url,
    url_host,
    is_http_url,
    is_safe_public_url,
    registrable_domain,
)
from .versioning import (
    parse_version,
    compare_versions,
    version_in_range,
    normalize_version_string,
)

__all__ = [
    "normalize_ws", "truncate", "strip_html", "escape_html",
    "escape_markdown_v2", "safe_json_loads", "coalesce",
    "dedupe_preserve_order", "slugify",
    "normalize_cve_id", "is_valid_cve_id", "extract_cve_ids",
    "normalize_cwe_id", "extract_cwe_ids", "normalize_ghsa_id",
    "cve_year", "cve_sort_key",
    "parse_timestamp", "to_epoch", "now_epoch", "iso_utc",
    "thai_date", "thai_datetime", "humanize_ago",
    "normalize_url", "url_host", "is_http_url", "is_safe_public_url",
    "registrable_domain",
    "parse_version", "compare_versions", "version_in_range",
    "normalize_version_string",
]
