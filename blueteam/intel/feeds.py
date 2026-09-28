"""
blueteam/intel/feeds.py — threat-feed framework: definitions, format parsers
(pure), a decompression-bomb guard, and an SSRF-guarded conditional-GET fetcher.

Safety posture (spec D2/D3, gติกา):
  * Feed URLs must be **https** and pass the **same SSRF guard** as Link Guard
    (:func:`blueteam.netprobe.screen_host` — resolve, reject private/loopback/
    metadata/CGNAT, re-resolve before connect to defeat rebinding).
  * **Conditional GET** (ETag / If-Modified-Since) -> 304 skips re-ingest.
  * **Decompression-bomb guard**: gzip/zip are expanded with a hard output cap
    and a max expansion ratio; anything over quarantines the sync.
  * A feed whose **license is uncertain is disabled by default** (``license_ok``).
  * Parsing is pure (bytes -> list of :class:`ParsedIOC`) and unit-tested offline;
    only :class:`FeedFetcher` touches the network, through an injectable transport.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .domain import IOCType, canonicalize, CanonicalizeError

# Absolute output cap for any single feed body after decompression (32 MiB).
_MAX_DECOMPRESSED_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class FeedDef:
    name: str
    url: str
    fmt: str                     # parser key (see _PARSERS)
    license: str = ""
    license_ok: bool = False     # uncertain license -> disabled by default
    enabled_default: bool = False
    source_weight: float = 0.5
    severity: str = "medium"
    default_ttl_days: int = 30
    notes: str = ""


@dataclass
class ParsedIOC:
    ioc_type: IOCType
    value: str                   # canonical (parser canonicalizes; drops invalid)
    family: str = ""
    tags: List[str] = field(default_factory=list)
    severity: str = ""
    reference: str = ""


@dataclass
class FetchResult:
    status: int                  # 200 | 304 | 0 (blocked/error)
    body: bytes = b""
    etag: str = ""
    last_modified: str = ""
    error: str = ""
    from_cache: bool = False     # True on 304


# ---------------- decompression-bomb guard ----------------

def decompress_guard(raw: bytes, *, encoding: str = "", url: str = "",
                     max_ratio: float = 200.0,
                     max_bytes: int = _MAX_DECOMPRESSED_BYTES) -> bytes:
    """Return the decompressed body, or raise ValueError if it looks like a bomb.

    Handles gzip (by content-encoding or magic) and single-entry zip. Streams in
    chunks so a malicious archive can't blow up memory before the cap trips.
    """
    enc = (encoding or "").lower()
    is_gzip = "gzip" in enc or raw[:2] == b"\x1f\x8b"
    is_zip = url.lower().endswith(".zip") or raw[:2] == b"PK"
    if not (is_gzip or is_zip):
        return raw
    in_size = max(1, len(raw))
    out = bytearray()
    ratio_cap = int(min(max_bytes, in_size * max_ratio))
    if is_gzip:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            while True:
                chunk = gz.read(65536)
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > ratio_cap or len(out) > max_bytes:
                    raise ValueError("decompression bomb: gzip output exceeds cap")
        return bytes(out)
    # zip: read the first file entry only, guarded by declared + actual size
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        names = zf.namelist()
        if not names:
            return b""
        info = zf.getinfo(names[0])
        if info.file_size > max_bytes:
            raise ValueError("decompression bomb: zip declares oversize entry")
        with zf.open(names[0]) as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                out.extend(chunk)
                if len(out) > ratio_cap or len(out) > max_bytes:
                    raise ValueError("decompression bomb: zip output exceeds cap")
    return bytes(out)


# ---------------- format parsers (pure) ----------------

def _add(out: List[ParsedIOC], t: IOCType, value: str, **kw) -> None:
    try:
        canon = canonicalize(t, value)
    except CanonicalizeError:
        return
    out.append(ParsedIOC(ioc_type=t, value=canon, **kw))


def parse_plaintext_urls(raw: bytes, feed: FeedDef) -> List[ParsedIOC]:
    out: List[ParsedIOC] = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        _add(out, IOCType.URL, line, severity=feed.severity, reference=feed.name)
    return out


def parse_urlhaus_csv(raw: bytes, feed: FeedDef) -> List[ParsedIOC]:
    """URLhaus online.csv: id,dateadded,url,url_status,last_online,threat,tags,link,reporter."""
    out: List[ParsedIOC] = []
    text = raw.decode("utf-8", "replace")
    rows = csv.reader(io.StringIO(text))
    for row in rows:
        if not row or row[0].lstrip().startswith("#"):
            continue
        if len(row) < 3:
            continue
        url = row[2].strip().strip('"')
        threat = row[5].strip() if len(row) > 5 else ""
        tags = [t for t in (row[6].split(",") if len(row) > 6 else []) if t]
        _add(out, IOCType.URL, url, family=threat, tags=tags,
             severity=feed.severity, reference=feed.name)
    return out


def parse_threatfox_csv(raw: bytes, feed: FeedDef) -> List[ParsedIOC]:
    """ThreatFox CSV: first_seen,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,..."""
    out: List[ParsedIOC] = []
    text = raw.decode("utf-8", "replace")
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#") or len(row) < 4:
            continue
        value = row[2].strip().strip('"')
        tf_type = row[3].strip().strip('"').lower()
        family = row[5].strip().strip('"') if len(row) > 5 else ""
        t = _THREATFOX_TYPE.get(tf_type)
        if t == IOCType.IP and tf_type == "ip:port":
            value = value.rsplit(":", 1)[0]        # "1.2.3.4:443" -> "1.2.3.4"
        elif t is None:
            if tf_type.startswith("ip") and ":" in value:
                value = value.rsplit(":", 1)[0]
                t = IOCType.IP
            else:
                continue
        _add(out, t, value, family=family, severity=feed.severity, reference=feed.name)
    return out


def parse_threatfox_json(raw: bytes, feed: FeedDef) -> List[ParsedIOC]:
    """ThreatFox API export: {"data": {id: [{ioc, ioc_type, malware, ...}]}} or a list."""
    out: List[ParsedIOC] = []
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return out
    data = doc.get("data", doc) if isinstance(doc, dict) else doc
    items = []
    if isinstance(data, dict):
        for v in data.values():
            items.extend(v if isinstance(v, list) else [v])
    elif isinstance(data, list):
        items = data
    for it in items:
        if not isinstance(it, dict):
            continue
        value = str(it.get("ioc") or it.get("ioc_value") or "").strip()
        tf_type = str(it.get("ioc_type") or "").lower()
        family = str(it.get("malware") or it.get("malware_printable") or "")
        t = _THREATFOX_TYPE.get(tf_type)
        if t == IOCType.IP and tf_type == "ip:port" and ":" in value:
            value = value.rsplit(":", 1)[0]
        elif t is None and tf_type.startswith("ip") and ":" in value:
            value, t = value.rsplit(":", 1)[0], IOCType.IP
        if t is None:
            continue
        _add(out, t, value, family=family, severity=feed.severity, reference=feed.name)
    return out


def parse_malwarebazaar_csv(raw: bytes, feed: FeedDef) -> List[ParsedIOC]:
    """MalwareBazaar full.csv: first_seen,sha256,md5,sha1,reporter,file_name,...,signature."""
    out: List[ParsedIOC] = []
    text = raw.decode("utf-8", "replace")
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].lstrip().startswith("#") or len(row) < 2:
            continue
        sha256 = row[1].strip().strip('"')
        signature = row[8].strip().strip('"') if len(row) > 8 else ""
        _add(out, IOCType.SHA256, sha256, family=signature,
             severity=feed.severity, reference=feed.name)
    return out


def parse_cisa_kev_json(raw: bytes, feed: FeedDef) -> List[ParsedIOC]:
    """CISA KEV catalog JSON -> ADVISORY IOCs (reporting only, never matched)."""
    out: List[ParsedIOC] = []
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return out
    for v in doc.get("vulnerabilities", []):
        cve = str(v.get("cveID") or "").strip()
        if not cve:
            continue
        name = str(v.get("vulnerabilityName") or "")
        _add(out, IOCType.ADVISORY, cve, family=str(v.get("product") or ""),
             tags=[name] if name else [], severity="high", reference=feed.name)
    return out


_THREATFOX_TYPE = {
    "url": IOCType.URL, "domain": IOCType.DOMAIN, "ip:port": IOCType.IP,
    "ip": IOCType.IP, "md5_hash": IOCType.MD5, "sha1_hash": IOCType.SHA1,
    "sha256_hash": IOCType.SHA256, "email": IOCType.EMAIL,
}

_PARSERS: Dict[str, Callable[[bytes, FeedDef], List[ParsedIOC]]] = {
    "plaintext_urls": parse_plaintext_urls,
    "urlhaus_csv": parse_urlhaus_csv,
    "threatfox_csv": parse_threatfox_csv,
    "threatfox_json": parse_threatfox_json,
    "malwarebazaar_csv": parse_malwarebazaar_csv,
    "cisa_kev_json": parse_cisa_kev_json,
}


def parse_feed(feed: FeedDef, raw: bytes) -> List[ParsedIOC]:
    parser = _PARSERS.get(feed.fmt)
    if parser is None:
        return []
    return parser(raw, feed)


# ---------------- feed definitions loader ----------------

def load_feed_defs(path: str) -> Dict[str, FeedDef]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    out: Dict[str, FeedDef] = {}
    for entry in doc.get("feeds", []):
        try:
            fd = FeedDef(
                name=entry["name"], url=entry["url"], fmt=entry["fmt"],
                license=entry.get("license", ""),
                license_ok=bool(entry.get("license_ok", False)),
                enabled_default=bool(entry.get("enabled_default", False)),
                source_weight=float(entry.get("source_weight", 0.5)),
                severity=entry.get("severity", "medium"),
                default_ttl_days=int(entry.get("default_ttl_days", 30)),
                notes=entry.get("notes", ""))
        except (KeyError, TypeError, ValueError):
            continue
        out[fd.name] = fd
    return out


# ---------------- SSRF-guarded conditional-GET fetcher ----------------

# transport(url, headers, timeout) -> (status, resp_headers, body_bytes)
Transport = Callable[[str, Dict[str, str], float], Tuple[int, Dict[str, str], bytes]]


class FeedFetcher:
    """Fetches a feed over https with SSRF screening, conditional GET and a
    decompression-bomb guard. The transport and resolver are injectable so the
    whole thing is testable offline."""

    def __init__(self, *, screen_host=None, resolver=None, transport: Optional[Transport] = None,
                 timeout_s: float = 20.0, max_decompress_ratio: float = 200.0,
                 max_body_bytes: int = _MAX_DECOMPRESSED_BYTES):
        self._screen_host = screen_host
        self._resolver = resolver
        self._transport = transport
        self._timeout = timeout_s
        self._max_ratio = max_decompress_ratio
        self._max_bytes = max_body_bytes

    def _screen(self, url: str) -> Tuple[bool, str]:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False, "feed url must be https"
        host = parsed.hostname or ""
        if self._screen_host is None:
            return True, "ok"          # screening disabled (tests inject transport)
        resolver = self._resolver
        if resolver is None:
            from ..netprobe import _default_resolver
            resolver = _default_resolver
        safe, reason, _ips = self._screen_host(host, resolver)
        return safe, reason

    def fetch(self, feed: FeedDef, *, etag: str = "", last_modified: str = "") -> FetchResult:
        safe, reason = self._screen(feed.url)
        if not safe:
            return FetchResult(status=0, error=f"SSRF guard: {reason}")
        headers = {"User-Agent": "sombra-guardian-intel/0.8", "Accept-Encoding": "gzip"}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        transport = self._transport or self._default_transport
        try:
            status, resp_headers, body = transport(feed.url, headers, self._timeout)
        except Exception as exc:                       # noqa: BLE001 — network is best-effort
            return FetchResult(status=0, error=f"fetch failed: {type(exc).__name__}")
        if status == 304:
            return FetchResult(status=304, from_cache=True,
                               etag=etag, last_modified=last_modified)
        if status != 200:
            return FetchResult(status=status, error=f"http {status}")
        lc = {k.lower(): v for k, v in resp_headers.items()}
        try:
            body = decompress_guard(body, encoding=lc.get("content-encoding", ""),
                                    url=feed.url, max_ratio=self._max_ratio,
                                    max_bytes=self._max_bytes)
        except ValueError as exc:
            return FetchResult(status=0, error=str(exc))
        return FetchResult(status=200, body=body,
                           etag=lc.get("etag", ""), last_modified=lc.get("last-modified", ""))

    def _default_transport(self, url: str, headers: Dict[str, str], timeout: float):
        """Blocking stdlib transport with re-resolve-before-connect (rebind guard).

        Run this in an executor; it is never called on the event loop directly.
        """
        import urllib.request
        # Re-screen immediately before connecting (defeat DNS rebinding).
        safe, reason = self._screen(url)
        if not safe:
            raise OSError(f"SSRF guard (reconnect): {reason}")
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - https enforced
                raw = resp.read(self._max_bytes + 1)
                if len(raw) > self._max_bytes:
                    raise ValueError("feed body exceeds size cap")
                return resp.status, dict(resp.headers.items()), raw
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items() if exc.headers else {}), b""


__all__ = ["FeedDef", "ParsedIOC", "FetchResult", "FeedFetcher", "decompress_guard",
           "parse_feed", "load_feed_defs", "_PARSERS"]
