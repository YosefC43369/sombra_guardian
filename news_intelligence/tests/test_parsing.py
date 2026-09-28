"""Tests for the HTML/metadata/schema/author/date parsers (pure, offline)."""
from news_intelligence.parsing.html_parser import HTMLParser, strip_html
from news_intelligence.parsing.metadata_parser import MetadataParser
from news_intelligence.parsing.schema_parser import SchemaParser
from news_intelligence.parsing.author_parser import AuthorParser
from news_intelligence.parsing.publication_parser import parse_date
from news_intelligence.parsing.readability import ReadabilityExtractor

HTML = """<html><head><title>Story Title</title>
<meta property="og:title" content="OG Title">
<meta property="og:description" content="A summary here">
<meta property="article:published_time" content="2025-09-24T10:00:00Z">
<meta name="author" content="By Jane Doe, Senior Reporter">
<link rel="canonical" href="https://ex.com/canonical">
<script type="application/ld+json">
{"@type":"NewsArticle","headline":"LD Headline","datePublished":"2025-09-24",
"author":{"name":"Jane Doe"},"articleBody":"APT29 used Cobalt Strike.",
"inLanguage":"en"}</script>
</head><body><nav>menu</nav><article><p>This is the main article body about
APT29 and CVE-2024-1234 exploited in the wild against Ukraine.</p>
<p>A second paragraph with more detail on Cobalt Strike beacons and evil.com.</p>
</article><footer>copyright</footer></body></html>"""


def test_html_to_text_drops_boilerplate():
    text = strip_html(HTML)
    assert "APT29" in text
    assert "menu" not in text or "copyright" not in text


def test_metadata_parser():
    m = MetadataParser().parse(HTML)
    assert m["title"] == "OG Title"
    assert m["summary"] == "A summary here"
    assert m["canonical_url"] == "https://ex.com/canonical"
    assert m["published"].startswith("2025-09-24")


def test_schema_parser():
    s = SchemaParser().parse(HTML)
    assert s["title"] == "LD Headline"
    assert "Cobalt Strike" in s["body"]
    assert s["language"] == "en"


def test_author_parser_cleans_and_splits():
    ap = AuthorParser()
    assert ap.primary("By Jane Doe, Senior Reporter") == "Jane Doe"
    assert ap.parse("Alice Smith and Bob Jones") == ["Alice Smith", "Bob Jones"]


def test_publication_parser_formats():
    assert parse_date("Wed, 24 Sep 2025 10:00:00 GMT") > 0
    assert parse_date("2025-09-24T10:00:00Z") > 0
    assert parse_date("2025-09-24") > 0
    assert parse_date("garbage") == 0.0


def test_readability_extracts_body():
    body = ReadabilityExtractor().extract(HTML)
    assert "APT29" in body
    assert "main article body" in body
