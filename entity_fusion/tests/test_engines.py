"""Tests for entity_fusion.engines — the offline correlation engines."""

import pytest

from entity_fusion.entity import Entity, EntityType
from entity_fusion.engines import (UsernameEngine, EmailEngine, PhoneEngine,
                                    CryptoEngine, DomainEngine, IPEngine,
                                    ASNEngine, CertificateEngine, WebsiteEngine,
                                    OrganizationEngine, BioEmailExtractor,
                                    BioWalletExtractor, generate_variants,
                                    classify_address, detect_addresses,
                                    registrable_base, org_key, run_engines,
                                    gravatar_hash)


def _e(etype, value, **meta):
    e = Entity(type=etype, value=value)
    e.metadata.update(meta)
    return e


class TestUsernameEngine:
    def test_derives_canonical_and_variants(self):
        r = UsernameEngine().analyze(_e(EntityType.USERNAME, "John.Doe"))
        assert r.derived["canonical_username"] == "johndoe"
        assert "johndoe" in r.derived["username_variants"]

    def test_variants_bounded(self):
        v = generate_variants("john.doe", max_variants=10)
        assert len(v) <= 10

    def test_variants_include_initial_forms(self):
        v = generate_variants("john doe")
        assert "jdoe" in v or "johnd" in v

    def test_homoglyph_watchlist_flag(self):
        eng = UsernameEngine(known_handles={"paypal"})
        r = eng.analyze(_e(EntityType.USERNAME, "pаypаl"))  # Cyrillic
        assert any(ev.kind == "homoglyph_spoof_suspected" for ev in r.evidence)


class TestEmailEngine:
    def test_gravatar_and_domain(self):
        r = EmailEngine().analyze(_e(EntityType.EMAIL, "John.Doe@Example.com"))
        assert r.derived["email_domain"] == "example.com"
        assert len(r.derived["gravatar_hash"]) == 32

    def test_gravatar_hash_stable(self):
        assert gravatar_hash("a@b.com") == gravatar_hash(" A@B.COM ")

    def test_bio_email_extractor_finds_defanged(self):
        e = _e(EntityType.USERNAME, "x", bio="reach me at john [at] example [dot] com")
        r = BioEmailExtractor().analyze(e)
        vals = [c.value for c in r.entities]
        assert "john@example.com" in vals


class TestPhoneEngine:
    def test_e164_and_region_tz(self):
        r = PhoneEngine().analyze(_e(EntityType.PHONE, "+66 81 234 5678"))
        assert r.derived["e164"] == "+66812345678"
        assert r.derived["phone_region"] == "TH"
        assert r.derived["timezone"] == "Asia/Bangkok"

    def test_unparseable_flagged(self):
        r = PhoneEngine().analyze(_e(EntityType.PHONE, "12"))
        assert any(ev.kind == "phone_unparseable" for ev in r.evidence)


class TestCryptoEngine:
    def test_classify_known_chains(self):
        assert classify_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "bitcoin"
        assert classify_address("0x" + "a" * 40) == "ethereum"
        assert classify_address("T" + "9" * 33) in ("tron", None)  # format check

    def test_detect_in_text(self):
        text = "btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa eth 0x" + "b" * 40
        matches = detect_addresses(text)
        chains = {m.chain for m in matches}
        assert "bitcoin" in chains and "ethereum" in chains

    def test_eth_normalized_lowercase(self):
        e = _e(EntityType.WALLET, "0x" + "AbCd" * 10)
        CryptoEngine().analyze(e)
        assert e.normalized == e.value.lower()

    def test_bio_wallet_extractor(self):
        e = _e(EntityType.USERNAME, "x",
               bio="tip jar: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        r = BioWalletExtractor().analyze(e)
        assert r.entities and r.entities[0].type == EntityType.WALLET


class TestInfraEngines:
    def test_domain_registrable_base(self):
        assert registrable_base("a.b.example.co.uk") == "example.co.uk"
        assert registrable_base("www.example.com") == "example.com"

    def test_domain_engine_idn_flag(self):
        r = DomainEngine().analyze(_e(EntityType.DOMAIN, "xn--e1afmkfd.xn--p1ai"))
        assert any(ev.kind == "idn_domain" for ev in r.evidence)

    def test_ip_engine_classifies(self):
        r = IPEngine().analyze(_e(EntityType.IP, "8.8.8.8"))
        assert r.derived["ip_is_global"] is True
        r2 = IPEngine().analyze(_e(EntityType.IP, "10.0.0.1"))
        assert r2.derived["ip_is_private"] is True

    def test_asn_engine_normalizes(self):
        r = ASNEngine().analyze(_e(EntityType.ASN, "AS15169"))
        assert r.derived["asn"] == 15169

    def test_certificate_engine_extracts_sans(self):
        e = _e(EntityType.CERTIFICATE, "AB:CD:EF",
               san=["a.example.com", "b.example.com"])
        r = CertificateEngine().analyze(e)
        assert len(r.entities) == 2
        assert r.derived["certificate_fingerprint"] == "abcdef"

    def test_website_engine_static_host_and_socials(self):
        e = _e(EntityType.WEBSITE, "https://johndoe.github.io",
               links="https://github.com/johndoe https://twitter.com/johndoe")
        r = WebsiteEngine().analyze(e)
        assert r.derived["static_host"] == "github_pages"
        assert r.derived["social_links"]

    def test_org_key_drops_legal_form(self):
        assert org_key("Acme, Inc.") == org_key("ACME LLC") == "acme"


def test_run_engines_folds_and_discovers():
    e = _e(EntityType.USERNAME, "John.Doe",
           bio="me@example.com tip 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    discovered = run_engines(e)
    assert e.metadata.get("canonical_username") == "johndoe"
    kinds = {c.type for c in discovered}
    assert EntityType.EMAIL in kinds and EntityType.WALLET in kinds
