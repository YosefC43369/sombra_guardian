"""Tests for content analysis: topics, domains/URLs, content reuse."""

from __future__ import annotations

import pytest

from behavioral_intelligence.models import Observation
from behavioral_intelligence.content import (url_behavior, domain_behavior,
                                             content_reuse, topic_evolution,
                                             analyze_reposts, analyze_threads,
                                             extract_entities)
from behavioral_intelligence.tests.conftest import at


def test_url_normalization_strips_tracking():
    n = url_behavior.normalize_url("HTTP://Example.com/Path/?utm_source=x&a=1#frag")
    assert n == "https://example.com/Path?a=1"
    assert url_behavior.categorize("https://github.com/a/b") == "code"
    assert url_behavior.categorize("https://bit.ly/x") == "shortener"


def test_domain_registrable_folding():
    assert domain_behavior.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert domain_behavior.registrable_domain("sub.example.com") == "example.com"


def test_domain_transitions():
    early = [Observation(platform="x", account_id="a", timestamp=at(0),
                         urls=["https://old.com/1"])]
    late = [Observation(platform="x", account_id="a", timestamp=at(30),
                        urls=["https://new.com/1"])]
    trans = domain_behavior.domain_transitions(early, late)
    assert "new.com" in trans["appeared"]
    assert "old.com" in trans["disappeared"]


def test_content_reuse_exact_and_simhash():
    obs = [Observation(platform="a", account_id="x", timestamp=at(0),
                       text="the exact same message about osint tooling"),
           Observation(platform="b", account_id="y", timestamp=at(1),
                       text="the exact same message about osint tooling"),
           Observation(platform="c", account_id="z", timestamp=at(2),
                       text="a completely different unrelated sentence entirely")]
    exact = content_reuse.detect_reuse(obs, method="exact")
    assert len(exact) == 1 and exact[0].similarity == 1.0
    sim = content_reuse.detect_reuse(obs, method="simhash", threshold=0.9)
    assert any(r.similarity >= 0.9 for r in sim)


def test_content_reuse_similarity_functions():
    a = "the quick brown fox jumps".split()
    b = "the quick brown fox jumps".split()
    c = "totally different words here now".split()
    assert content_reuse.cosine_similarity(a, b) == pytest.approx(1.0)
    assert content_reuse.cosine_similarity(a, c) < 0.3
    assert content_reuse.simhash_similarity(content_reuse.simhash(a),
                                            content_reuse.simhash(b)) == 1.0


def test_topic_evolution_emerged_faded():
    obs = []
    # January (days 0-27): one topic; February (days 31-58): a different topic.
    # Clean month boundaries so the latest period's terms are genuinely new.
    for d in range(0, 28):
        obs.append(Observation(platform="x", account_id="a", timestamp=at(d),
                               text="programming python coding software"))
    for d in range(31, 59):
        obs.append(Observation(platform="x", account_id="a", timestamp=at(d),
                               text="cybersecurity exploit malware threat"))
    evo = topic_evolution.analyze_evolution(obs, granularity="month")
    assert len(evo.periods) == 2
    assert evo.emerged      # cybersecurity terms new in February
    assert evo.faded        # programming terms gone from February


def test_repost_and_thread_analysis():
    obs = [Observation(platform="x", account_id="a", timestamp=at(0),
                       content_type="post", text="original", observation_id="p1"),
           Observation(platform="x", account_id="b", timestamp=at(0, 21),
                       content_type="reply", text="reply", in_reply_to="p1",
                       thread_id="t1", observation_id="p2"),
           Observation(platform="x", account_id="a", timestamp=at(0, 22),
                       content_type="reply", text="re-reply", in_reply_to="p2",
                       thread_id="t1", observation_id="p3")]
    rep = analyze_reposts(obs)
    assert rep.reply_ratio > 0
    threads = analyze_threads(obs)
    assert threads.thread_count >= 1
    assert threads.max_depth >= 2


def test_entity_extraction():
    obs = [Observation(platform="x", account_id="a", timestamp=at(0),
                       text="contact me@example.com or @handle, IP 8.8.8.8")]
    res = extract_entities(obs)
    assert "email" in res.by_category
    assert "8.8.8.8" in res.by_category.get("ipv4", [])
