"""
cve_tracker.ingestion — fetch, normalize, validate, de-duplicate, enrich.

The HTTP/rate-limit/retry machinery (:mod:`fetcher`, :mod:`ratelimit`) and the
pure transform (:mod:`normalizer`, :mod:`validator`, :mod:`deduplicator`,
:mod:`pipeline`) live here. The engine wires a shared :class:`HttpFetcher` into
the sources and runs their output through :class:`IngestionPipeline`.
"""

from .fetcher import HttpFetcher, FetchResult
from .ratelimit import RateLimiterRegistry, TokenBucket
from .pipeline import IngestionPipeline, PipelineResult
from .normalizer import normalize_record
from .validator import validate_record, is_publishable, filter_valid
from .deduplicator import merge_two, dedupe_batch

__all__ = [
    "HttpFetcher", "FetchResult",
    "RateLimiterRegistry", "TokenBucket",
    "IngestionPipeline", "PipelineResult",
    "normalize_record", "validate_record", "is_publishable", "filter_valid",
    "merge_two", "dedupe_batch",
]
