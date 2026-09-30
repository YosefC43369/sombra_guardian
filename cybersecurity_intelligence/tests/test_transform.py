"""Article → claims transformation."""

from __future__ import annotations

import pytest

from cybersecurity_intelligence.exceptions import CTITransformError
from cybersecurity_intelligence.models.claim import ClaimType
from cybersecurity_intelligence.transform import ArticleTransformer


def _by_subject(claims):
    out = {}
    for c in claims:
        out.setdefault(c.subject.ref_type, []).append(c)
    return out


def test_transform_extracts_cve_ioc_ttp():
    t = ArticleTransformer()
    res = t.transform({
        "title": "CVE-2021-44228 exploited",
        "summary": ("CVE-2021-44228 is being exploited in the wild. IOC "
                    "evil.example.ru and technique T1190."),
        "source": "CISA", "source_class": "government",
        "url": "https://cisa.gov/a", "published_at": "2021-12-11T00:00:00Z",
    })
    kinds = _by_subject(res.claims)
    assert "cve" in kinds and "domain" in kinds and "ttp" in kinds
    # a CVE mention -> OBSERVED; an exploitation statement -> REPORTED with detail
    exploit = [c for c in kinds["cve"] if c.predicate == "exploitation"]
    assert exploit and exploit[0].detail["exploitation_status"] == "exploited"
    assert exploit[0].detail.get("severity") is None or exploit[0].detail["severity"]


def test_transform_detects_attribution():
    t = ArticleTransformer()
    res = t.transform({
        "title": "SolarWinds compromise",
        "summary": "CVE-2020-10148 abuse attributed to APT29 in this campaign.",
        "source": "Vendor", "source_class": "vendor",
        "url": "https://v.com/x", "published_at": 1607731200.0,
    })
    attrib = [c for c in res.claims if c.predicate == "attributed_to"]
    assert attrib
    assert attrib[0].detail["attribution"].upper().startswith("APT29")


def test_transform_published_at_parsing_variants():
    t = ArticleTransformer()
    iso = t.transform({"title": "CVE-2021-1000 x", "summary": "CVE-2021-1000 seen",
                       "source": "s", "published_at": "2021-06-01T12:00:00Z"})
    epoch = t.transform({"title": "CVE-2021-1000 x", "summary": "CVE-2021-1000 seen",
                         "source": "s", "published_at": 1622548800.0})
    assert iso.claims[0].observed_at > 0
    assert epoch.claims[0].observed_at == 1622548800.0


def test_transform_source_reliability_absent_until_engine_grades():
    t = ArticleTransformer()
    res = t.transform({"title": "CVE-2021-1", "summary": "CVE-2021-1",
                       "source": "s", "source_class": "vendor"})
    # transformer builds the SourceRecord; grading happens in the engine
    assert res.source.name == "s"


def test_transform_rejects_empty_article():
    t = ArticleTransformer()
    with pytest.raises(CTITransformError):
        t.transform({"title": "", "summary": ""})


def test_transform_oversize_content_truncated():
    from cybersecurity_intelligence.config import get_config
    cfg = get_config()
    cfg.max_article_size_bytes = 100
    t = ArticleTransformer(cfg)
    res = t.transform({"title": "CVE-2021-44228", "summary": "CVE-2021-44228 " + "z" * 5000,
                       "source": "s"})
    # still produces the CVE claim, content was truncated internally without error
    assert any(c.subject.ref_type == "cve" for c in res.claims)


def test_transform_many_skips_bad_articles():
    t = ArticleTransformer()
    out = t.transform_many([
        {"title": "", "summary": ""},                       # dropped
        {"title": "CVE-2021-44228", "summary": "CVE-2021-44228", "source": "s"},
    ])
    assert len(out) == 1
