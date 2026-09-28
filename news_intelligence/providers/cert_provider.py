"""news_intelligence.providers.cert_provider — national/sector CERT feed provider."""
from __future__ import annotations
from ..ingestion.cert_ingestor import CERTIngestor
from .base import BaseProvider


class CERTProvider(BaseProvider):
    name = "cert"
    ingestor_cls = CERTIngestor


__all__ = ["CERTProvider"]
