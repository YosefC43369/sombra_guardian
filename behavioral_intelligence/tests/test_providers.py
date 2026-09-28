"""Tests for passive providers (offline normalization)."""

from __future__ import annotations

from behavioral_intelligence.providers import RSSProvider, ActivityPubProvider
from behavioral_intelligence.providers.base import BehaviorProvider


def test_rss_rss2_parsing():
    xml = """<?xml version="1.0"?><rss version="2.0"><channel><title>Sec Feed</title>
    <item><title>OSINT tooling</title><description>about cybersecurity</description>
    <link>https://ex.com/1</link><pubDate>Mon, 05 Jan 2026 20:00:00 +0000</pubDate>
    <category>osint</category><category>infosec</category></item></channel></rss>"""
    obs = RSSProvider().normalize(xml)
    assert len(obs) == 1
    assert obs[0].content_type.value == "article"
    assert "osint" in obs[0].hashtags
    assert obs[0].hour_utc == 20
    assert obs[0].source_url == "https://ex.com/1"


def test_rss_atom_parsing():
    atom = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
    <title>Blog</title><entry><title>Post</title><summary>content here</summary>
    <updated>2026-02-01T10:00:00Z</updated>
    <link href="https://blog.example/p1"/></entry></feed>"""
    obs = RSSProvider().normalize(atom)
    assert len(obs) == 1
    assert obs[0].source_url == "https://blog.example/p1"


def test_activitypub_outbox_parsing():
    payload = {"orderedItems": [
        {"type": "Create", "actor": "https://m.social/users/alice",
         "published": "2026-01-05T20:00:00Z",
         "object": {"type": "Note", "content": "<p>hello #osint</p>",
                    "id": "https://m.social/1",
                    "tag": [{"type": "Hashtag", "name": "#osint"},
                            {"type": "Mention", "name": "@bob"}]}},
        {"type": "Announce", "actor": "https://m.social/users/alice",
         "published": "2026-01-06T10:00:00Z",
         "object": "https://other.social/9"}]}
    obs = ActivityPubProvider().normalize(payload)
    assert len(obs) == 2
    note = obs[0]
    assert note.account_id == "alice"
    assert "osint" in note.hashtags
    assert "bob" in note.mentions
    assert "hello" in note.text          # HTML stripped
    assert obs[1].content_type.value == "repost"


def test_validate_rejects_futuristic_and_empty():
    p = BehaviorProvider()
    from behavioral_intelligence.models import Observation
    import time
    future = Observation(platform="x", account_id="a", timestamp=time.time() + 10**7)
    assert not p.validate(future)
    empty = Observation()      # no platform/account/url
    assert not p.validate(empty)
    ok = Observation(platform="x", account_id="a", timestamp=time.time() - 100)
    assert p.validate(ok)
