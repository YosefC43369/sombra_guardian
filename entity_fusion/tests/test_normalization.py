"""Tests for entity_fusion.normalization — the canonicalization pipeline and the
type-specific canonicalizers. Pure stdlib, no network."""

import pytest

from entity_fusion import normalization as n


class TestGeneralPipeline:
    def test_nfkc_folds_fullwidth(self):
        assert n.normalize_text("ｊｏｈｎ") == "john"

    def test_strips_emoji_and_zero_width(self):
        assert n.normalize_text("john​doe\U0001f600") == "johndoe"

    def test_collapses_whitespace(self):
        assert n.normalize_text("  John   Doe \n") == "john doe"

    def test_casefold_optional(self):
        assert n.normalize_text("ABC", casefold=False) == "ABC"
        assert n.normalize_text("ABC", casefold=True) == "abc"

    def test_empty_returns_empty_not_none(self):
        assert n.normalize_text(None) == ""
        assert n.normalize_text("") == ""


class TestSkeletonAndHomoglyph:
    def test_skeleton_folds_separators(self):
        assert n.skeleton("john.doe") == n.skeleton("john_doe") == "johndoe"

    def test_cyrillic_homoglyph_detected(self):
        # 'раypаl' uses Cyrillic а and р
        assert n.looks_confusable("paypal", "pаypаl")

    def test_greek_omicron_homoglyph(self):
        assert n.looks_confusable("google", "gοogle")

    def test_distinct_strings_not_confusable(self):
        assert not n.looks_confusable("alice", "bob")

    def test_identical_not_confusable(self):
        assert not n.looks_confusable("alice", "alice")


class TestEmail:
    def test_gmail_dot_and_plus_folding(self):
        assert n.canonical_email("j.o.h.n+tag@gmail.com") == "john@gmail.com"

    def test_googlemail_folds_like_gmail(self):
        assert n.canonical_email("john.doe@googlemail.com") == "johndoe@googlemail.com"

    def test_non_gmail_keeps_dots(self):
        assert n.canonical_email("john.doe@example.com") == "john.doe@example.com"

    def test_plus_stripped_everywhere(self):
        assert n.canonical_email("a.b+x@example.com") == "a.b@example.com"

    def test_invalid_returns_empty(self):
        assert n.canonical_email("not-an-email") == ""
        assert n.canonical_email("a@b") == ""

    def test_email_domain(self):
        assert n.email_domain("x+y@Example.COM") == "example.com"


class TestUsername:
    def test_separator_folding(self):
        for v in ("John.Doe", "john_doe", "john-doe", "JOHN DOE", "@john.doe"):
            assert n.canonical_username(v) == "johndoe"

    def test_username_core_strips_numeric_suffix(self):
        assert n.username_core("johndoe1990") == "johndoe"
        assert n.username_core("john_doe_42") == "johndoe"

    def test_leet_defang(self):
        assert n.leet_defang("h4ck3r") == "hacker"


class TestPhone:
    def test_e164_from_formatted(self):
        assert n.canonical_phone("+66 81 234-5678") == "+66812345678"
        # a well-formed US number with punctuation
        assert n.canonical_phone("+1 (415) 555-0123") == "+14155550123"

    def test_double_zero_prefix(self):
        assert n.canonical_phone("0066812345678") == "+66812345678"

    def test_default_cc_applied(self):
        assert n.canonical_phone("081-234-5678", default_cc="66") == "+66812345678"

    def test_too_short_rejected(self):
        assert n.canonical_phone("12345") == ""

    def test_region_hint(self):
        assert n.phone_region_hint("+66812345678") == "TH"
        assert n.phone_region_hint("+14155550123") == "NANP"


class TestUrlAndDomain:
    def test_url_strips_tracking_and_default_port(self):
        got = n.canonical_url("HTTPS://Example.com:443/path/?utm_source=x&a=1#frag")
        assert got == "https://example.com/path?a=1"

    def test_url_adds_scheme(self):
        assert n.canonical_url("example.com").startswith("https://example.com")

    def test_domain_lowercase_and_strip(self):
        assert n.canonical_domain("HTTPS://WWW.Example.com./") in (
            "www.example.com", "example.com")

    def test_domain_wildcard_stripped(self):
        assert n.canonical_domain("*.example.com") == "example.com"


class TestScriptSpecific:
    def test_arabic_strips_tashkeel(self):
        assert n.normalize_arabic("مُحَمَّد") == n.normalize_arabic("محمد")

    def test_hebrew_strips_niqqud(self):
        assert n.normalize_hebrew("שָׁלוֹם") == n.normalize_hebrew("שלום")

    def test_thai_strips_tone_marks(self):
        # same base consonants, tone mark removed
        assert n.normalize_thai("ก่") == "ก"

    def test_cjk_fullwidth_fold(self):
        assert n.normalize_cjk("ＡＢＣ") == "ABC"


def test_dispatch_normalize_value():
    assert n.normalize_value("email", "A.B+c@gmail.com") == "ab@gmail.com"
    assert n.normalize_value("username", "John.Doe") == "johndoe"
    assert n.normalize_value("phone", "+1 415 555 0123") == "+14155550123"
    assert n.normalize_value("domain", "Example.com") == "example.com"
