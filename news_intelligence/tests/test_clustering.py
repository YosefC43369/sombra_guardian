"""Tests for duplicate/event/topic/campaign clustering + similarity primitives."""
from news_intelligence.clustering.similarity import (simhash, simhash_similar,
    minhash, minhash_jaccard, TFIDF, tokenize)
from news_intelligence.clustering.duplicate_cluster import DuplicateDetector
from news_intelligence.clustering.event_cluster import EventClusterer
from news_intelligence.clustering.topic_cluster import TopicClusterer
from news_intelligence.clustering.campaign_cluster import CampaignClusterer
from news_intelligence.extraction import EntityExtractor

_EX = EntityExtractor()


def _mk(title, summary, dom, off, now):
    from news_intelligence.models.article import Article
    a = Article(title=title, summary=summary, url=f"https://{dom}/{abs(hash(title))%9999}",
                source_name=dom, source_domain=dom, source_class="vendor",
                publication_date=now - off * 3600)
    _EX.extract_from_article(a)
    a.evidence = [a.as_evidence().to_dict()]
    a.simhash = simhash(title + " " + summary)
    return a


def test_simhash_similarity():
    a = simhash("APT29 exploits CVE-2024-1234 with Cobalt Strike")
    b = simhash("APT29 exploits CVE-2024-1234 with Cobalt Strike")
    assert simhash_similar(a, b, threshold=0)


def test_minhash_jaccard():
    m1 = minhash("the quick brown fox jumps")
    m2 = minhash("the quick brown fox jumps over")
    assert minhash_jaccard(m1, m2) > 0.4


def test_tfidf_pairs():
    idx = TFIDF({"a": "ransomware lockbit banks", "b": "ransomware lockbit finance",
                 "c": "unrelated weather sports"})
    pairs = dict(((x, y), s) for x, y, s in idx.pairs_above(0.1))
    assert ("a", "b") in pairs
    assert pairs[("a", "b")] > 0


def test_duplicate_detection(now):
    arts = [
        _mk("APT29 exploits CVE-2024-1234 with Cobalt Strike", "Ukraine hit", "a.com", 1, now),
        _mk("APT29 exploits CVE-2024-1234 with Cobalt Strike", "Ukraine hit", "b.com", 2, now),
        _mk("Totally different weather story", "sunny day", "c.com", 3, now),
    ]
    clusters = DuplicateDetector().mark_duplicates(arts)
    assert len(clusters) == 1
    assert len(clusters[0].article_ids) == 2
    dups = [a for a in arts if a.duplicate_of]
    assert len(dups) == 1


def test_event_clustering_by_shared_signals(now):
    arts = [
        _mk("APT29 uses CVE-2024-1234", "Cobalt Strike against Ukraine", "a.com", 1, now),
        _mk("Cozy Bear CVE-2024-1234 campaign", "APT29 Cobalt Strike", "b.com", 2, now),
        _mk("Unrelated data breach", "some company leaked data", "c.com", 3, now),
    ]
    clusters = EventClusterer(window_hours=72).cluster(arts)
    assert clusters
    top = clusters[0]
    assert top.size >= 2
    assert any("cve" in s for s in top.signals)


def test_topic_clustering(now):
    arts = [
        _mk("LockBit hits banks", "LockBit ransomware", "a.com", 1, now),
        _mk("LockBit resurgence", "LockBit ransomware rising", "b.com", 2, now),
    ]
    topics = TopicClusterer(min_articles=2).cluster_by_entity(arts)
    assert any("lockbit" in t.label.lower() for t in topics)


def test_campaign_clustering_preserves_sources(now):
    arts = [
        _mk("APT29 uses CVE-2024-1234", "Cobalt Strike Ukraine", "a.com", 1, now),
        _mk("Cozy Bear CVE-2024-1234", "APT29 Cobalt Strike", "b.com", 2, now),
    ]
    camps = CampaignClusterer(now=now).build(arts)
    assert camps
    assert camps[0].independent_report_count >= 1
