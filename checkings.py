# Standard library imports
import ast
import asyncio
import logging
import os
import random
import re
import ssl
import sys
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock
from urllib.parse import quote, urlparse

# Third party imports
import aiodns
from alive_progress import alive_bar
from aiohttp import ClientSession, TCPConnector, http_exceptions
from aiohttp.resolver import ThreadedResolver
from aiohttp.client_exceptions import (
    ClientConnectorDNSError,
    ClientConnectorError,
    ClientPayloadError,
    ServerDisconnectedError,
)
from aiohttp_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError
from socid_extractor import extract, mutate_url  # type: ignore[import-not-found]

# Local imports
from . import errors
from .activation import ParsingActivator, import_aiohttp_cookies
from .error_detection import detect_error_page
from .errors import CheckError
from .executors import AsyncioQueueGeneratorExecutor
from .result import MaigretCheckResult, MaigretCheckStatus, KeywordMatchStatus, SiteResult
from .sites import MaigretDatabase, MaigretSite
from .utils import ascii_data_display, get_random_user_agent, is_plausible_username


_DNS_ERROR_MARKERS = (
    "could not contact dns servers",  # aiohttp + aiodns wording
    "name or service not known",       # glibc getaddrinfo
    "nodename nor servname",           # macOS getaddrinfo
    "temporary failure in name resolution",  # glibc EAI_AGAIN
    "getaddrinfo failed",              # generic socket error
)