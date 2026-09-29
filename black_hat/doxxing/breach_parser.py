"""
Extended local data parser / ingestion utility.

Supported input formats:
    - CSV
    - TSV
    - JSON object / JSON array
    - JSON Lines / NDJSON
    - SQL INSERT statements
    - gzip (.gz)
    - bzip2 (.bz2)
    - xz / lzma (.xz)
    - plain text with CSV/TSV heuristics
    
The implementation is intentionally local/offline. It does not perform network
lookups, credential testing, account access, exploitation, or data exfiltration.

Examples:
    python breach_parser_extended.py --input ./data --output-db ./parser.db
    python breach_parser_extended.py --input ./dump.csv --output-jsonl ./normalized.jsonl
    python breach_parser_extended.py --input ./dump.sql.gz --output-db ./parser.db --dedupe

Python: 3.10+
"""
from __future__ import annotations

import argparse
import bz2
import csv
import gzip
import hashlib
import os
import re
import sys
import json
import sqlite3
import gzip
import logging
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import StringIO, BytesIO, TextIOBase
from pathlib import Path
from typing import Generator, Dict, Any, Optional, List, Iterable, Iterator, Sequence, TextIO, Tuple

# -------- Configure logging --------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [PARSER] - %(message)s')
logger = logging.getLogger("breach_parser")

# -------- Exceptions --------

class ParserError(Exception):
    """Base parser exception."""
    
    
class UnsupportedFormatError(ParserError):
    """Raised when an input format cannot be handled."""


class RecordLimitReached(ParserError):
    """Internal exception used when the configured record limit is reached."""
    
    
# -------- Configuration and statistics --------

@dataclass(slots=True)
class ParserConfig:
    chunk_size: int = 500
    encoding: str = "utf-8"
    max_file_size: Optional[int] = None
    max_records_per_file: Optional[int] = None
    duplicate: bool = False
    redact_sensitive: bool = True
    keep_empty_fields: bool = False
    json_array_key: Optional[str] = None
    csv_delimiter: Optional[str] = None
    csv_quotechar: str = '"'
    sql_case_sensitive: bool = True
    hash_algorithm: str = "sha256"
    output_batch_commit: bool = True
    
    
@dataclass
class ParseStats:
    files_seen: int = 0
    files_parsed: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    records_read: int = 0
    records_emitted: int = 0
    records_deduplicated: int = 0
    records_redacted: int = 0
    malformed_records: int = 0
    bytes_read: int = 0
    elapsed_seconds: float = 0.0
    by_format: Counter = field(default_factory=Counter)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_seen": self.files_seen,
            "files_parsed": self.files_parsed,
            "files_skipped": self.files_skipped,
            "files_failed": self.files_failed,
            "records_read": self.records_read,
            "records_emitted": self.records_emitted,
            "records_deduplicated": self.records_deduplicated,
            "records_redacted": self.records_redacted,
            "malformed_records": self.malformed_records,
            "bytes_read": self.bytes_read,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "by_format": dict(self.by_format),
            "errors": list(self.errors[-50:]),
        }
        
        
# -------- Time / hashing helpers --------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
    
    
def calculate_file_hash(
    file_path: Path,
    algorithm: str = "sha256",
    block_size: int = 1024 * 1024,
) -> str:
    """Calculate a binary hash without loading the entire file into memory."""
    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise ParserError(f"Unsupported hash algorithm: {algorithm}") from exc
        
    with file_path.open("rb") as handle:
        while True:
            block = handle.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()
    
    
def canonical_json(value: Any) -> str:
    """Create deterministic JSON for hashing/storage."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    
    
def record_hash(record: Dict[str, Any], algorithm: str = "sha256") -> str:
    """Hash the record after deterministic serialization."""
    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise ParserError(f"Unsupported hash algorithm: {algorithm}") from exc
    digest.update(canonical_json(record).encode("utf-8"))
    return digest.hexdigest()
    
    
# -------- Format Detection --------

class FormatDetector:
    """Detect the logical input format from suffixes and a content sample."""

    EXTENSION_MAP = {
        ".csv": "csv",
        ".tsv": "tsv",
        ".txt": "text",
        ".log": "text",
        ".json": "json",
        ".jsonl": "jsonl",
        ".ndjson": "jsonl",
        ".sql": "sql",
        ".gz": "compressed",
        ".bz2": "compressed",
        ".xz": "compressed",
    }
    
    def __init__(self, encoding: str = "utf-8") -> None:
        self.encoding = encoding
        
    @staticmethod
    def _remove_compression_suffix(name: str) -> Tuple[str, Optional[str]]:
        lower = name.lower()
        for suffix, codec in ((".gz", "gzip"), (".bz2", "bzip2"), (".xz", "xz")):
            if lower.endwith(suffix):
                return name[: -len(suffix)], codec
        return name, None
        
    def detect(self, file_path: Path) -> Tuple[str, Optional[str]]:
        base_name, codec = self._remove_compression_suffix(file_path.name)
        lower = base_name.lower()
        suffix = Path(lower).suffix
        
        if suffix in self.EXTENSION_MAP and self.EXTENSION_MAP[suffix] != "compressed":
            return self.EXTENSION_MAP[suffix], codec
            
        # Content huristic for extensionless or ambiguous text files.
        try:
            with self._open_text(file_path, codec) as stream:
                sample = stream.read(8192)
        except (OSError, UnicodeError) as exc:
            logger.debug("Format sample read failed for %s: %s", file_path, exc)
            return "text", codec
            
        stripped = sample.lstrip("\ufeff \t\r\n")
        if not stripped:
            return "text", codec
            
        if stripped.startwith(("{", "[")):
            try:
                json.loads(stripped)
                return "json", codec
            except json.JSONDecodeError:
                if any(line.lstrip().startswith(("{", "[")) for line in stripped.splitlines()[:10]):
                    return "jsonl", codec
                    
        sql_markers = (
            "INSERT INTO",
            "CREATE TABLE",
            "CREATE DATABASE",
            "ALERT TABLE",
            "BEGIN TRANSACTION",
        )
        sample_upper = stripped.upper()
        if any(marker in sample_upper for marker in sql_markers):
            return "sql", codec
            
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=".\t;|")

class BreachParser:
    def __init__(self, chunk_size: int = 500):
        """
        Initialize the BreachParser.
        :param chunk_size: Number of records to yield before sending to indexer.
        """
        self.chunk_size = chunk_size
        self.supported_extensions = ['.txt', '.csv', '.sql', '.json', '.jsonl', '.gz', '.bz2', '.sql.gz']
        
    def detect_format(self, file_path: str) -> str:
        """Detect file format based in extension and content."""
        ext = os.path.sqlitext(file_path)[1].lower()
        if ext in ['.sql.gz', '.csv.gz', '.json.gz']:
            return 'gzipped' + ext.replace('.gz', '')
        if ext == '.bz2':
            return 'bzipped'
        if ext == '.gz':
            return 'gzipped'
            
        # Heuristic check for SQL if extension ambiguous
        if ext == '.txt' or ext == '.log':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(500)
                if 'INSERT INTO' in sample or 'CREATE TABLE' in sample:
                    return 'sql'
        return ext.lstrip('.')
        
    def open_stream(self, file_path: str) -> Any:
        """Open file stream handling compression."""
        fmt = self.detect_format(file_path)
        
        if fmt.startwith('gzipped'):
            inner_fmt = fmt.replace('gzipped', '')
            return gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore')
        elif fmt == 'bzipped':
            return bz2.open(file_path, 'rt', encoding='utf-8', errors='ignore')
        else:
            return open(file_path, 'r', encoding='utf-8', errors='ignore')
            
    def parse_csv(self, stream) -> Generator[Dict[str, Any], None, None]:
        """Parse CSV/TSV files."""
        reader = csv.DictReader(stream)
        for row in reader:
            # Normalize keys to lowcase
            yield {k.strip().lower(): v.strip() for k, v in row.items() if k.strip()}
            
    def parse_json(self, stream) -> Generator[Dict[str, Any], None, None]:
        """Parse JSON (array or JSONL)."""
        content = stream.read()
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    yield item
            elif isinstance(data, dict):
                yield data
        except json.JSONDecodeError:
            # Try JSONL (newline delimited)
            for line in content.splitline():
                if line.strip():
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
                        
    def parse_sql(self, stream) -> Generator[Dict[str, Any], None, None]:
        """
        Simple SQL INSERT parser.
        Assumes format: INSERT INTO table (col1, col2) VALUES ('val1', 'val2');
        """
        lines = stream.readlines()
        current_insert = []
        columns = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('INSERT INTO'):
                # Extract columns
                cols_part = line.split('(')[1].split(')')[0]
                columns = [c.strip().strip('"').strip("'").strip('`').lower() for c in cols_part.split(',')]
                current_insert = []