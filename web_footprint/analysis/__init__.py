"""
web_footprint.analysis — the offline (no-network) analysis layer.

Everything here is a pure function of already-fetched public data: subdomain-role
classification by name, technology fingerprinting, reference extraction (with
secret redaction), passive security-signal analysis, and exposure
classification. Keeping analysis pure means it is deterministic, trivially unit
-tested without a network, and cannot itself reach out to a target.
"""

from . import subdomain_roles, tech, extract, security_signals, exposure

__all__ = ["subdomain_roles", "tech", "extract", "security_signals", "exposure"]
