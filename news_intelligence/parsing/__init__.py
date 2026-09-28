"""
news_intelligence.parsing — HTML → normalized article field extraction.

Pure parsers (no network): HTML→text, readability main-content, OpenGraph/meta,
schema.org JSON-LD, author bylines, and publication dates. The ingestion layer
composes these to normalize a fetched page; each is independently unit-tested
against fixtures.
"""

from .html_parser import HTMLParser, strip_html, HAVE_BS4
from .readability import ReadabilityExtractor
from .metadata_parser import MetadataParser
from .schema_parser import SchemaParser
from .author_parser import AuthorParser
from .publication_parser import PublicationParser, parse_date

__all__ = ["HTMLParser", "strip_html", "HAVE_BS4", "ReadabilityExtractor",
           "MetadataParser", "SchemaParser", "AuthorParser", "PublicationParser",
           "parse_date"]
