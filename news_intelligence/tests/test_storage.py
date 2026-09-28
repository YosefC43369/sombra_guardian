"""Tests for the SQLite store: articles, entities, IOC cross-source, kv, migrations."""
from news_intelligence.models.article import Article
from news_intelligence.models.entity import EntityMention, EntityType


def test_schema_version(store):
    assert store.schema_version() == 1


def test_save_and_get_article(store):
    a = Article(title="t", summary="s", url="https://x/1", source_name="X",
                source_domain="x.com", source_class="vendor")
    a.add_mentions([EntityMention(EntityType.CVE, surface="CVE-2024-1")])
    store.save_article(a)
    got = store.get_article(a.article_id)
    assert got is not None
    assert got.cve_mentions == ["CVE-2024-1"]


def test_article_exists_dedup(store):
    a = Article(title="dup", summary="x", url="https://x/1", source_name="X",
                source_domain="x.com")
    store.save_article(a)
    assert store.article_exists(content_hash=a.content_hash)


def test_entity_counts_and_cross_source(store, now):
    for i, dom in enumerate(["a.com", "b.com"]):
        a = Article(title=f"art{i}", summary="evil.com", url=f"https://{dom}/{i}",
                    source_name=dom, source_domain=dom, publication_date=now)
        a.add_mentions([EntityMention(EntityType.CVE, surface="CVE-2024-9"),
                        EntityMention(EntityType.DOMAIN, surface="evil.com")])
        store.save_article(a)
    counts = store.entity_counts("cve")
    assert counts[0]["value"] == "CVE-2024-9"
    assert counts[0]["count"] == 2
    xs = store.ioc_cross_source(min_domains=2)
    assert xs and xs[0]["value"] == "evil.com"


def test_kv_roundtrip(store):
    store.kv_set("ns", "k", {"a": 1})
    assert store.kv_get("ns", "k") == {"a": 1}


def test_provider_state(store):
    store.set_provider_state("rss", "http://x", etag="W/1")
    st = store.get_provider_state("rss", "http://x")
    assert st["etag"] == "W/1"
