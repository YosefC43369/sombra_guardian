"""Tests for RSS/Atom/JSON-Feed + specialized ingestors (pure parse, offline)."""
import time
from news_intelligence.ingestion.rss_ingestor import RSSIngestor
from news_intelligence.ingestion.atom_ingestor import AtomIngestor
from news_intelligence.ingestion.json_feed import JSONFeedIngestor
from news_intelligence.ingestion.cisa_ingestor import CISAKEVIngestor
from news_intelligence.ingestion.github_blog_ingestor import GitHubBlogIngestor
from news_intelligence.ingestion.nvd_ingestor import NVDIngestor
from news_intelligence.models.source import NewsSource, SourceCategory, ReliabilityClass

RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>Feed</title>
<item><title>APT29 exploits CVE-2024-1234</title><link>https://ex/a1</link>
<description>Cozy Bear used Cobalt Strike, evil[.]com</description>
<pubDate>Wed, 24 Sep 2025 10:00:00 GMT</pubDate><author>Jane Doe</author></item>
<item><title>Second story</title><link>https://ex/a2</link>
<description>Something else</description><pubDate>Thu, 25 Sep 2025 08:00:00 GMT</pubDate></item>
</channel></rss>"""

ATOM = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<title>AtomFeed</title>
<entry><title>Atom item CVE-2024-9999</title>
<link href="https://ex/atom1"/><summary>LockBit ransomware note</summary>
<published>2025-09-24T10:00:00Z</published><author><name>Bob</name></author></entry>
</feed>"""

JSONF = """{"version":"https://jsonfeed.org/version/1.1","title":"JF",
"items":[{"id":"1","url":"https://ex/jf1","title":"JSON item",
"summary":"IcedID loader seen","date_published":"2025-09-24T10:00:00Z",
"author":{"name":"Carol"}}]}"""


def _src():
    return NewsSource(name="Feed", category=SourceCategory.NEWS_ORGANIZATION,
                      reliability_class=ReliabilityClass.NEWS_OUTLET,
                      rss_url="https://ex/feed")


def test_rss_parse():
    r = RSSIngestor().parse(RSS, source=_src())
    assert len(r.articles) == 2
    a = r.articles[0]
    assert "APT29" in a.title
    assert a.author == "Jane Doe"
    assert a.publication_date > 0
    assert a.evidence  # self-citation attached


def test_atom_parse():
    r = AtomIngestor().parse(ATOM, source=_src())
    assert len(r.articles) == 1
    assert r.provider == "atom"
    assert r.articles[0].url == "https://ex/atom1"


def test_json_feed_parse():
    r = JSONFeedIngestor().parse(JSONF, source=_src())
    assert len(r.articles) == 1
    assert r.articles[0].author == "Carol"


def test_cisa_kev_parse_marks_exploited():
    kev = ('{"vulnerabilities":[{"cveID":"CVE-2023-9999","vendorProject":"Ivanti",'
           '"product":"CSA","vulnerabilityName":"RCE","dateAdded":"2025-01-15",'
           '"shortDescription":"bad","requiredAction":"patch"}]}')
    r = CISAKEVIngestor().parse(kev)
    assert len(r.articles) == 1
    assert r.articles[0].detail["kev"] is True
    assert r.articles[0].cve_mentions == [] or "CVE-2023-9999" in r.articles[0].detail["cve"]


def test_github_api_parse():
    js = ('[{"ghsa_id":"GHSA-xxxx","summary":"RCE in lib","html_url":'
          '"https://github.com/advisories/GHSA-xxxx","published_at":'
          '"2025-09-01T00:00:00Z","severity":"high","cve_id":"CVE-2025-1"}]')
    r = GitHubBlogIngestor().parse_api(js)
    assert len(r.articles) == 1
    assert r.articles[0].cve_mentions == ["CVE-2025-1"]


def test_nvd_parse():
    js = ('{"vulnerabilities":[{"cve":{"id":"CVE-2025-5","published":'
          '"2025-09-01T00:00:00.000","descriptions":[{"lang":"en","value":'
          '"A flaw"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":'
          '"CRITICAL","baseScore":9.8}}]}}}]}')
    r = NVDIngestor().parse(js)
    assert len(r.articles) == 1
    assert r.articles[0].detail["severity"] == "CRITICAL"
    assert r.articles[0].cve_mentions == ["CVE-2025-5"]
