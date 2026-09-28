"""news_intelligence.providers.nvd_provider — NVD CVE feed provider."""
from __future__ import annotations
from ..ingestion.nvd_ingestor import NVDIngestor
from .base import BaseProvider


class NVDProvider(BaseProvider):
    name = "nvd"
    ingestor_cls = NVDIngestor

    def collect(self, source=None, *, store=None):  # pragma: no cover
        return self.make_ingestor().run(store=store)


__all__ = ["NVDProvider"]
