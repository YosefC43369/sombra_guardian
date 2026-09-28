"""
news_intelligence.correlation — explainable, evidence-gated correlation.

Every correlator returns ``NewsRelationship`` objects that record the shared signals,
supporting articles and computed confidence behind each link. Nothing is asserted as
fact; a correlation says "these co-occur in public reporting", never "X did Y".
"""

from .base import NewsRelationship, BaseCorrelator
from .entity_correlation import EntityCorrelator
from .article_correlation import ArticleCorrelator
from .report_correlation import ReportCorrelator, CorroborationResult
from .infrastructure_correlation import InfrastructureCorrelator
from .campaign_correlation import CampaignCorrelator
from .topic_correlation import TopicCorrelator

__all__ = ["NewsRelationship", "BaseCorrelator", "EntityCorrelator",
           "ArticleCorrelator", "ReportCorrelator", "CorroborationResult",
           "InfrastructureCorrelator", "CampaignCorrelator", "TopicCorrelator"]
