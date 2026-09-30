"""
cve_tracker.alerts — filter, format, route, throttle and deliver CVE alerts.

The :class:`AlertDispatcher` is the entry point; it uses :mod:`routing` +
:mod:`filters` to decide recipients, :mod:`formatter` (+ :mod:`templates`) to
build the Thai message, and :class:`AlertThrottler` to pace delivery under
Telegram flood control.
"""

from .dispatcher import AlertDispatcher
from .formatter import format_new_cve, format_updated_cve, format_compact
from .throttler import AlertThrottler
from .routing import route
from .digest import DigestBuilder, DigestOptions, build_digest
from . import filters, templates

__all__ = [
    "AlertDispatcher", "format_new_cve", "format_updated_cve", "format_compact",
    "AlertThrottler", "route", "filters", "templates",
    "DigestBuilder", "DigestOptions", "build_digest",
]
