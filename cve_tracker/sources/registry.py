"""
cve_tracker.sources.registry — the plugin-style source registry.

New sources are added by registering a factory, never by editing the engine
(rule §41). The engine asks the registry to build the enabled sources for a
given config; a source whose config is disabled is skipped, and a factory that
raises is isolated and logged so one broken adapter can't stop the rest.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List

from ..config import CVETrackerConfig, SourceConfig
from .base import CVESource

logger = logging.getLogger("modbot.cve.registry")

# factory: (SourceConfig) -> CVESource
SourceFactory = Callable[[SourceConfig], CVESource]


class SourceRegistry:
    """Maps a source name to its factory. Order of registration is preserved,
    which becomes the default polling order."""

    def __init__(self):
        self._factories: Dict[str, SourceFactory] = {}

    def register(self, name: str, factory: SourceFactory) -> None:
        if name in self._factories:
            logger.warning("CVE SOURCE REGISTRY | duplicate registration for %s (overwriting)", name)
        self._factories[name] = factory

    def unregister(self, name: str) -> None:
        self._factories.pop(name, None)

    def names(self) -> List[str]:
        return list(self._factories)

    def is_registered(self, name: str) -> bool:
        return name in self._factories

    def build_enabled(self, config: CVETrackerConfig) -> List[CVESource]:
        """Instantiate every enabled, registered source for this config."""
        built: List[CVESource] = []
        for name, factory in self._factories.items():
            sc = config.source(name)
            if sc is None or not sc.enabled:
                continue
            try:
                built.append(factory(sc))
            except Exception:
                logger.exception("CVE SOURCE REGISTRY | factory for %s failed; skipping", name)
        return built

    def build_one(self, name: str, config: CVETrackerConfig):
        sc = config.source(name)
        factory = self._factories.get(name)
        if sc is None or factory is None:
            return None
        try:
            return factory(sc)
        except Exception:
            logger.exception("CVE SOURCE REGISTRY | factory for %s failed", name)
            return None


def default_registry() -> SourceRegistry:
    """Build the registry with all built-in sources registered. Imports are
    local so registering doesn't force httpx import until a source is built."""
    reg = SourceRegistry()
    from .nvd import NVDSource
    from .cve_org import CVEOrgSource
    from .cisa_kev import CISAKEVSource
    from .github_advisories import GitHubAdvisorySource
    from .vendor_advisories import VendorAdvisorySource
    from .epss import EPSSSource

    reg.register("nvd", lambda sc: NVDSource(sc))
    reg.register("cve_org", lambda sc: CVEOrgSource(sc))
    reg.register("cisa_kev", lambda sc: CISAKEVSource(sc))
    reg.register("github_advisory", lambda sc: GitHubAdvisorySource(sc))
    reg.register("vendor_advisory", lambda sc: VendorAdvisorySource(sc))
    reg.register("epss", lambda sc: EPSSSource(sc))
    return reg
