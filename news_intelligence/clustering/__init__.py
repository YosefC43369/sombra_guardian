"""
news_intelligence.clustering — explainable duplicate / event / topic / campaign
clustering, plus the dependency-free similarity primitives they share.
"""

from .similarity import (tokenize, shingles, simhash, hamming, simhash_similar,
                         minhash, minhash_jaccard, jaccard, TFIDF)
from .duplicate_cluster import DuplicateDetector
from .event_cluster import EventClusterer
from .topic_cluster import TopicClusterer
from .campaign_cluster import CampaignClusterer

__all__ = ["tokenize", "shingles", "simhash", "hamming", "simhash_similar",
           "minhash", "minhash_jaccard", "jaccard", "TFIDF",
           "DuplicateDetector", "EventClusterer", "TopicClusterer",
           "CampaignClusterer"]
