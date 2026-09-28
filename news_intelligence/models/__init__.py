"""
news_intelligence.models — the typed news-intelligence domain layer.

Pure data + epistemics: no I/O, no telegram, no sqlite. Everything round-trips
through ``to_dict``/``from_dict`` losslessly and every analytical aggregate anchors
to evidence with an explainable confidence. The evidence/confidence primitives are
re-exported from ``threat_actor_intelligence`` so the news engine speaks the same
evidence language as the CTI and behavioural engines.
"""

from .evidence import (TLP, SourceClass, SOURCE_CLASS_WEIGHT, EvidenceRef,
                       EvidenceBundle, source_class_for_category,
                       NEWS_CATEGORY_TO_SOURCE_CLASS)
from .confidence import (AssertionKind, ConfidenceModel, Assertion, Limitation,
                         band_for, confidence_from_evidence, STANDING_LIMITATIONS,
                         NEWS_STANDING_LIMITATIONS, news_confidence)
from .source import (SourceCategory, ReliabilityClass, RELIABILITY_WEIGHT,
                     NewsSource, domain_of)
from .feed import FeedFormat, Feed
from .entity import (EntityType, EntityMention, IOC_ENTITY_TYPES, normalize_value,
                     dedupe_mentions)
from .article import Article, content_hash
from .topic import ClusterKind, Topic, Cluster, NewsEvent
from .cve import CVENews, normalize_cve, is_cve
from .malware import MalwareNews, normalize_malware_name, malware_key
from .actor import ActorNews, normalize_actor_name, actor_key
from .campaign import (CampaignNews, DifferingClaim, normalize_campaign_name,
                       campaign_key)
from .report import ReportSection, NewsReport

__all__ = [
    # evidence / confidence
    "TLP", "SourceClass", "SOURCE_CLASS_WEIGHT", "EvidenceRef", "EvidenceBundle",
    "source_class_for_category", "NEWS_CATEGORY_TO_SOURCE_CLASS",
    "AssertionKind", "ConfidenceModel", "Assertion", "Limitation", "band_for",
    "confidence_from_evidence", "STANDING_LIMITATIONS",
    "NEWS_STANDING_LIMITATIONS", "news_confidence",
    # sources / feeds
    "SourceCategory", "ReliabilityClass", "RELIABILITY_WEIGHT", "NewsSource",
    "domain_of", "FeedFormat", "Feed",
    # entities / articles
    "EntityType", "EntityMention", "IOC_ENTITY_TYPES", "normalize_value",
    "dedupe_mentions", "Article", "content_hash",
    # aggregates
    "ClusterKind", "Topic", "Cluster", "NewsEvent",
    "CVENews", "normalize_cve", "is_cve",
    "MalwareNews", "normalize_malware_name", "malware_key",
    "ActorNews", "normalize_actor_name", "actor_key",
    "CampaignNews", "DifferingClaim", "normalize_campaign_name", "campaign_key",
    "ReportSection", "NewsReport",
]
