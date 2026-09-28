"""
threat_actor_intelligence.correlation — explainable, evidence-gated correlation.

Every correlator returns ``Relationship`` objects that name the *signal* that
produced them and carry the evidence + confidence behind them, plus (for actors
and malware) alias *merge candidates* that are always suggestions requiring
review — never automatic identity merges.
"""

from .base import (CorrelationResult, build_relationship, correlation_assertion)
from .alias_resolution import (AliasResolver, AliasIndex, MergeCandidate,
                               normalize_name, similarity)
from .actor_correlation import ActorCorrelator
from .campaign_correlation import CampaignCorrelator
from .malware_correlation import MalwareCorrelator
from .infrastructure_correlation import InfrastructureCorrelator
from .ioc_correlation import IOCCorrelator
from .report_correlation import ReportCorrelator, Corroboration

__all__ = ["CorrelationResult", "build_relationship", "correlation_assertion",
           "AliasResolver", "AliasIndex", "MergeCandidate", "normalize_name",
           "similarity", "ActorCorrelator", "CampaignCorrelator",
           "MalwareCorrelator", "InfrastructureCorrelator", "IOCCorrelator",
           "ReportCorrelator", "Corroboration"]
