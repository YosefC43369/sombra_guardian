"""
cve_tracker.version — single source of truth for the subsystem version.

Kept tiny and import-free so any module (including migrations and the plugin
suite) can read the version without pulling the whole package in. Mirrors the
``group_soc.version`` convention already used in this repo.
"""

# Semantic version of the CVE Intelligence & Tracking subsystem itself.
__version__ = "1.0.0"

# Schema version implemented by migrations/m0008_cve_tracker.py. When the DDL in
# that migration changes in a backward-incompatible way, bump this and add a new
# migration rather than editing the applied one (migrations are immutable once
# shipped — see migrations/base.py checksum()).
SCHEMA_VERSION = 1

# Human-readable codename, surfaced by /cve_status and the plugin metadata.
CODENAME = "sombra-cve-intel"
