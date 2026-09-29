"""
cybersecurity_intelligence.transform — public data → evidence-backed claims.

The transform layer is what makes this an intelligence platform rather than a news
reader (spec §32, §168). A raw article/advisory/report is turned into a graded
:class:`~cybersecurity_intelligence.models.source.SourceRecord` and a set of typed,
evidence-anchored :class:`~cybersecurity_intelligence.models.claim.Claim` objects,
reusing the proven IOC/CVE/TTP extractor from
``threat_actor_intelligence.ingestion.extract``. No claim is minted without a
citation back to the article it came from.
"""

from __future__ import annotations

from .news_transform import ArticleTransformer, TransformResult

__all__ = ["ArticleTransformer", "TransformResult"]
