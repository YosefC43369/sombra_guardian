"""news_intelligence.providers.cisa_provider — CISA advisory + KEV provider."""
from __future__ import annotations
from ..ingestion.cisa_ingestor import CISAIngestor, CISAKEVIngestor
from .base import BaseProvider


class CISAProvider(BaseProvider):
    name = "cisa"
    ingestor_cls = CISAIngestor


class CISAKEVProvider(BaseProvider):
    name = "cisa_kev"
    ingestor_cls = CISAKEVIngestor

    def collect(self, source=None, *, store=None):  # pragma: no cover
        return self.make_ingestor().run(store=store)


__all__ = ["CISAProvider", "CISAKEVProvider"]
