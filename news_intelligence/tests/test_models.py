"""Tests for the news-intelligence domain models + evidence/confidence reuse."""
import time
from news_intelligence.models.article import Article, content_hash
from news_intelligence.models.entity import EntityMention, EntityType, normalize_value
from news_intelligence.models.evidence import EvidenceRef, EvidenceBundle, SourceClass
from news_intelligence.models.confidence import news_confidence, NEWS_STANDING_LIMITATIONS
from news_intelligence.models.source import NewsSource, SourceCategory, ReliabilityClass
from news_intelligence.models.cve import normalize_cve, is_cve, CVENews
from news_intelligence.models.actor import normalize_actor_name, ActorNews
from news_intelligence.models.malware import normalize_malware_name


def test_article_roundtrip_and_buckets():
    a = Article(title="APT29 and CVE-2024-1234", summary="evil.com",
                url="https://x/1", source_name="X", source_class="vendor")
    a.add_mentions([EntityMention(EntityType.CVE, surface="CVE-2024-1234"),
                    EntityMention(EntityType.THREAT_ACTOR, surface="APT 29"),
                    EntityMention(EntityType.DOMAIN, surface="evil[.]com")])
    assert a.cve_mentions == ["CVE-2024-1234"]
    assert a.actor_mentions == ["APT29"]
    assert "evil.com" in a.iocs
    b = Article.from_dict(a.to_dict())
    assert b.cve_mentions == a.cve_mentions
    assert b.article_id == a.article_id


def test_entity_normalization():
    assert normalize_value(EntityType.THREAT_ACTOR, "APT 29") == "APT29"
    assert normalize_value(EntityType.CVE, "cve-2024-1") == "CVE-2024-1"
    assert normalize_value(EntityType.DOMAIN, "EVIL[.]COM") == "evil.com"


def test_cve_helpers():
    assert normalize_cve("cve-2024-1234") == "CVE-2024-1234"
    assert is_cve("CVE-2024-1234")
    assert not is_cve("not-a-cve")


def test_actor_alias_preserved_separately():
    prof = ActorNews(name="APT29", aliases=["Cozy Bear", "APT29"])
    assert "Cozy Bear" in prof.aliases
    assert "APT29" not in prof.aliases  # canonical is never an alias of itself


def test_news_confidence_carries_standing_limitations():
    b = EvidenceBundle([EvidenceRef(provider="a", source_class=SourceClass.VENDOR,
                                    observed_at=time.time())])
    cm = news_confidence(b, now=time.time())
    texts = {l.text for l in cm.limitations}
    assert any(t for t, _ in NEWS_STANDING_LIMITATIONS if t in texts)
    assert 0.0 <= cm.score <= 1.0


def test_evidence_dedup_by_ref_id():
    b = EvidenceBundle()
    r = EvidenceRef(provider="p", external_id="x", title="t")
    assert b.add(r) is True
    assert b.add(EvidenceRef(provider="p", external_id="x", title="t")) is False
    assert len(b) == 1


def test_source_maps_to_class():
    s = NewsSource(name="CISA", category=SourceCategory.GOVERNMENT_ADVISORY,
                   reliability_class=ReliabilityClass.OFFICIAL_GOVERNMENT)
    assert s.source_class == SourceClass.GOVERNMENT
    assert s.reliability_weight > 0.9
