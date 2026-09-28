"""news_intelligence.providers.vendor_provider — security-vendor blog provider."""
from __future__ import annotations
from ..ingestion.vendor_ingestor import VendorIngestor
from .base import BaseProvider


class VendorProvider(BaseProvider):
    name = "vendor"
    ingestor_cls = VendorIngestor

    def make_ingestor(self):
        ing = super().make_ingestor()
        return ing


__all__ = ["VendorProvider"]
