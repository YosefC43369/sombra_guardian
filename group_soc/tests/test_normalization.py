"""Normalization is the privacy boundary — verify PII never survives it."""

from __future__ import annotations

from group_soc.collector import EventRouter
from group_soc.normalization import Normalizer
from group_soc.normalization.context import extract_entities


def test_actor_id_is_hashed_not_raw():
    raw = EventRouter().route("message.received", {
        "chat_id": -100, "user_id": 777777, "message_id": 1,
        "text": "hello", "username": "secret_user", "display_name": "Real Name",
    })
    ev = Normalizer().normalize(raw)
    assert ev.actor_hash and ev.actor_hash != "777777"
    assert "777777" not in (ev.actor_hash or "")


def test_message_text_not_stored_raw():
    raw = EventRouter().route("message.received", {
        "chat_id": -100, "user_id": 1, "message_id": 1,
        "text": "my secret password is hunter2", "username": "u",
    })
    ev = Normalizer().normalize(raw)
    # only a hash + length are kept; the text and username never appear
    assert ev.content_hash is not None and ev.content_len > 0
    blob = str(ev.as_dict())
    assert "hunter2" not in blob and "secret password" not in blob
    assert "username" not in ev.context and "text" not in ev.context


def test_domains_extracted_and_defanged():
    raw = EventRouter().route("message.received", {
        "chat_id": -100, "user_id": 1, "message_id": 1,
        "text": "visit https://evil.example.com/path now",
    })
    ev = Normalizer().normalize(raw)
    domains = [e.key for e in ev.entities if e.kind == "domain"]
    assert any("evil[.]example[.]com" in d for d in domains)


def test_bot_join_maps_to_bot_added():
    raw = EventRouter().route("member.joined",
                              {"chat_id": -100, "user_id": 9, "is_bot": True})
    ev = Normalizer().normalize(raw)
    assert ev.event_type == "bot_added"


def test_ioc_confidence_normalized():
    raw = EventRouter().route("intel.ioc_matched", {
        "chat_id": -100, "ioc_type": "domain", "value_defanged": "bad[.]tld",
        "confidence": 90, "severity": "high"})
    ev = Normalizer().normalize(raw)
    assert 0.89 < ev.confidence < 0.91 and ev.severity == "high"


def test_extract_entities_dedup():
    ents = extract_entities("http://a.com http://a.com b.com")
    keys = [v for _, v in ents]
    # a.com appears once as url + once as domain, b.com as domain; no dup domains
    assert keys.count("a.com") <= 1
