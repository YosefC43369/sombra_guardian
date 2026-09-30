"""
cve_tracker.sources — source adapters and the plugin-style registry.

Import the registry helper and base types from here; concrete adapters are
imported lazily by the registry so the package import stays light.
"""

from .base import CVESource, FetchContext, SourceFetchResult
from .registry import SourceRegistry, default_registry

__all__ = [
    "CVESource", "FetchContext", "SourceFetchResult",
    "SourceRegistry", "default_registry",
]
