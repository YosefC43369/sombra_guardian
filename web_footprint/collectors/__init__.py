"""
web_footprint.collectors — the passive public-source collectors.

Every collector reads one public source and returns a uniform
:class:`CollectorResult`. The whole set is passive by construction (see
``base.py``): certificate transparency, public DNS over DoH, the Wayback web
archive, the target's own published ``/.well-known`` files, and public
repository references. ``default_collectors`` returns one instance of each; the
pipeline runs only those whose ``stage`` its mode enables.
"""

from .base import Collector, CollectorResult, CollectorStatus
from .certs import CertificateCollector
from .passive_dns import PassiveDNSCollector
from .archive import ArchiveCollector
from .wellknown import WellKnownCollector
from .repos import RepositoryCollector

__all__ = [
    "Collector", "CollectorResult", "CollectorStatus",
    "CertificateCollector", "PassiveDNSCollector", "ArchiveCollector",
    "WellKnownCollector", "RepositoryCollector",
    "default_collectors",
]


def default_collectors():
    """One instance of every built-in passive collector."""
    return [
        CertificateCollector(),
        PassiveDNSCollector(),
        ArchiveCollector(),
        WellKnownCollector(),
        RepositoryCollector(),
    ]
