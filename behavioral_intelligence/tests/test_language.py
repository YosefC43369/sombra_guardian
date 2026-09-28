"""Tests for linguistic analysis, with emphasis on Unicode/Thai/CJK handling."""

from __future__ import annotations

from behavioral_intelligence.models import Observation
from behavioral_intelligence.linguistic import (script_detector, language_detector,
                                                language_switching, transliteration,
                                                keyword_engine)
from behavioral_intelligence.tests.conftest import at


def test_script_detection_multiscript():
    assert script_detector.dominant_script("hello world") == "Latin"
    assert script_detector.dominant_script("สวัสดีครับ") == "Thai"
    assert script_detector.dominant_script("これはテスト") in ("Hiragana", "Katakana", "Han")
    assert script_detector.dominant_script("Привет мир") == "Cyrillic"
    assert script_detector.is_mixed_script("hello สวัสดี world เธอ")


def test_language_detection_across_scripts():
    assert language_detector.detect_language("The quick brown fox and the dog") == "en"
    assert language_detector.detect_language("สวัสดีครับ ผมชอบเขียนโปรแกรม") == "th"
    assert language_detector.detect_language("これはテストです ありがとう") == "ja"
    assert language_detector.detect_language("Привет как дела сегодня") == "ru"
    assert language_detector.detect_language("El gato está en la casa con") == "es"


def test_language_detection_empty_is_undetermined():
    d = language_detector.detect("")
    assert d.language == "und"
    assert d.confidence == 0.0


def test_language_switching_timeline_and_distribution():
    obs = []
    for d in range(0, 30):
        obs.append(Observation(platform="x", account_id="a", timestamp=at(d, 20),
                               text="hello world english text", language="en"))
    for d in range(30, 60):
        obs.append(Observation(platform="x", account_id="a", timestamp=at(d, 20),
                               text="สวัสดี ทดสอบ ภาษาไทย", language="th"))
    dist = language_switching.distribution(obs)
    assert set(dist.shares) == {"en", "th"}
    switches = language_switching.switches(obs)
    assert any(s.from_language == "en" and s.to_language == "th" for s in switches)
    timeline = language_switching.timeline(obs, granularity="month")
    assert len(timeline) >= 2


def test_transliteration_supporting_evidence_only():
    m = transliteration.compare_alias("สมชาย", "somchai")
    assert m.method == "romanization_table"
    assert m.similarity > 0.5
    m2 = transliteration.compare_alias("иван", "ivan")
    assert m2.similarity == 1.0
    # Han is explicitly unsupported (needs pinyin), reported not mishandled
    m3 = transliteration.compare_alias("北京", "beijing")
    assert m3.method == "unsupported_script"


def test_keyword_tokenizer_handles_thai_via_bigrams():
    toks = keyword_engine.tokenize("สวัสดีครับ hello world")
    # Latin words present, Thai run split into bigrams (non-empty)
    assert "hello" in toks and "world" in toks
    assert any(len(t) == 2 for t in toks)


def test_keyword_tfidf_ranking():
    obs = [Observation(platform="x", account_id="a", timestamp=at(i, 20),
                       text="cybersecurity osint threat intelligence") for i in range(10)]
    obs += [Observation(platform="x", account_id="a", timestamp=at(i, 21),
                        text="random unrelated filler content") for i in range(3)]
    kws = keyword_engine.extract_keywords(obs, top_n=5)
    terms = {k.term for k in kws}
    assert "cybersecurity" in terms or "osint" in terms
