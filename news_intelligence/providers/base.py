"""
news_intelligence.providers.base — the provider abstraction.

A *provider* binds a source category to the ingestor that collects it and exposes a
uniform ``collect(source, store)`` returning an ``IngestResult``. The orchestrator
picks a provider per source (by category) and never needs to know which concrete
ingestor is involved. Providers are thin: all parsing lives in ``ingestion``.
"""

from __future__ import annotations

from typing import Optional

from ..configuration import NewsIntelConfig, ProviderConfig
from ..ingestion.base import IngestResult, HTTPClient
from ..models.source import NewsSource


class BaseProvider:
    name = "base"
    ingestor_cls = None

    def __init__(self, *, config: Optional[NewsIntelConfig] = None,
                 http: Optional[HTTPClient] = None):
        self.config = config
        self.http = http

    def _provider_config(self) -> ProviderConfig:
        if self.config is not None:
            return self.config.provider(self.name)
        return ProviderConfig(name=self.name)

    def is_available(self) -> bool:
        return self._provider_config().is_available()

    def make_ingestor(self):
        pc = self._provider_config()
        ua = self.config.user_agent if self.config else "SombraGuardian-NI/2.0"
        kw = dict(user_agent=ua, timeout=pc.timeout_seconds,
                  rate_limit_per_min=pc.rate_limit_per_min,
                  api_key=pc.api_key() or "")
        if self.http is not None:
            kw["http"] = self.http
        return self.ingestor_cls(**kw)  # type: ignore

    def collect(self, source: NewsSource, *, store=None) -> IngestResult:  # pragma: no cover
        ing = self.make_ingestor()
        return ing.run(source=source, store=store)


__all__ = ["BaseProvider"]
