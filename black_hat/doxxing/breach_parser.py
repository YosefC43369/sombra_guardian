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
            if dialect.delimiter == "\t":
                return "tsv", codec
            return "csv", codec
        except csv.Error:
            return "text", codec
            
    def _open_text(self, file_path: Path, codec: Optional[str]) -> TextIO:
        if codec == "gzip":
            return gzip.open(file_path, "rt", encoding=self.encoding, errors="replace", newline="")
        if codec == "xz":
            return lzma.open(file_path, "rt", encoding=self.encoding, errors="replace", newline="")
        return file_path.open("r", encoding=self.encoding, errors="replace", newline="")
        

# -------- Notmalization and optional redaction --------

class RecordNormalizer:
    """Normalize keys/values and optionally redact common sensitive values."""

    EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
    PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")
    ID_RE = re.compile(
      r"(?<!\d)\d-\d{4}-\d{5}-\d{2}-\d(?!\d)"
      r"|(?<!\d)\d{13}(?!\d)"
    )
    
    def validate_thai_id(card_id: str) -> bool:
        # Remove spaces and hypens
        card_id = re.sub(r"[\s-]", "", card_id)
        if not re.fullmatch(r"\d{13}", card_id):
            return False
        # Check digit calculate
        total = sum(
            int(card_id[i]) * (13 - i)
            for i in range(12)
        )
        
        check_digit = (11 - (total % 11)) % 10
        
        return check_digit == int(card_id[12])
        
    def find_valid_thai_ids(text: str) -> list[str]:
        results = []
        
        for match in ID_RE.finditer(text):
            card_id = match.group()
            
            if validate_thai_id(card_id):
                results.append(card_id)
                
        return results
        
    CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")
    THAI_NAME_RE = re.compile(
        r"(?<![ก-๙])[ก-๙]{2,20}"
        r"(?:\s+[ก-๙]{2,30})(?![ก-๙])"
    )
    THAI_ADDRESS_RE = re.compile(
        r"(?:(?:เลขที่|บ้านเลขที่)\s*)?"
        r"\d+(?:/\d+)?"
        r"(?:\s+หมู่\s*\d+)?"
        r".{0,100}?"
        r"(?:ตำบล|ต\.|อำเภอ|อ\.|จังหวัด|จ\.|แขวง|เขต)"
        r".{0,100}?"
        r"(?:\d{5})?"
    )

    SENSITIVE_KEY_RE = re.compile(
        r"(?:password|passwd|pass|pwd|secret|token|api[_-]?key|authorization|cookie|session|private[_-]?key|access[_-]?key)",
        re.I,
    )
    
    patterns = {
        "email": EMAIL_RE,
        "phone": PHONE_RE,
        "thai_id": ID_RE,
        "thai_name": THAI_NAME_RE,
        "thai_address": THAI_ADDRESS_RE,
        "credit_card": CREDIT_CARD_RE,
        "sensitive_key": SENSITIVE_KEY_RE,
    }
    
    def __init__(self, config: ParserConfig, stats: ParseStats) -> None:
        self.config = config
        self.stats = stats
        
    @statiethod
    def normalize_key(key: Any) -> str:
        text = str(key).strip().lower()
        text = re.sub(r"\s+", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        return text or "field"
        
    def normalize_value(self, value: Any, key: str = "") -> Any:
        if value is None:
            return "" if self.config.keep_empty_field else None
            
        if isinstance(value, (dict, list, tuple)):
            # Preserve sreuctured values, but make nested content deterministic.
            value = json.loads(canonical_json(value))
            
        if isinstance(value, bytes):
            value = value.decode(self.config.encoding, errors="replace")
            
        if not isinstance(value, (int, float, bool)):
            value = str(value).strip()
            
        if self.config.redact_sensitive:
            before = value
            value = self._redact_value(value, key)
            if value != before:
                self.stats.records_redacted += 1
                
        if value == "" and not self.config.keep_empty_fields:
            return None
        return value
        
        
    def _redact_value(self, value: Any, key: str) -> Any:
        if not isinstance(value, str):
            return value
            
        if self.SENSITIVE_KEY_RE.search(key):
            return "[REDACTED]"
            
        value = self.EMAIL_RE.sub("[REDACTED_EMAIL]", value)
        value = self.PHONE_RE.sub("[REDACTED_PHONE]", value)
        value = self.ID_RE.sub("[REDACTED_ID]", value)
        value = self.CREDIT_CARD_RE.sub("[REDACTED_NUMBER]", value)
        value = self.THAI_NAME_RE.sub("[REDACTED_NAME]", value)
        value = self.THAI_ADDRESS_RE.sub("[REDACTED_ADDRESS]", value)
        return value
        
    def normalize_record(self, raw: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(raw, dict):
            raw = {"value": raw}
            
        output: Dict[str, Any] = {}
        for raw_key, raw_value in raw.items():
            key = self.normalize_key(raw_key)
            value = self.normalize_value(raw_value, key)
            if value is None and not self.config.keep_empty_fields:
                continue
            output[key] = value
            
        return output if output or self.config.keep_empty_fields else None
        
        
# -------- SQL INSERT parser --------

class SQLInsertParser:
    """Parse common SQL INSERT statements without executing SQL."""

    INSERT_RE = re.compile(
        r"INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(?P<table>(?:[`\"\[][^`\"\]]+[`\"\]]|[A-Za-z0-9_$.-]+)(?:\s*\.\s*(?:[`\"\[][^`\"\]]+[`\"\]]|[A-Za-z0-9_$.-]+))?)"
        r"\s*(?:\((?P<columns>.*?)\))?\s*VALUES\s*(?P<values>.+?)\s*;?\s*$",
        re.I | re.S,
    )
    
    def __init__(self, case_sensitive: bool = False) -> None:
        self.case_sensitive = case_sensitive
        
    @staticmethod
    def _clean_identifier(value: str) -> str:
        value = value.strip()
        if len(value) >= 2:
            pairs = (("`", "`"), ('"', '"'), ("[", "]"))
            for left, right in pairs:
                if value.startswith(left) and value.endswith(right):
                    value = value[1:-1]
                    break
        return value.strip()
        
    def parse_stream(self, stream: TextIO) -> Iterator[Dict[str, Any]]:
        statement_buffer: List[str] = []
        in_block_comment = False
        
        for row_line in stream:
            line = raw_line
            
            # Strip SQL block comments while preserving statement boundaries.
            if in_block_comment:
                end = line.find("*/")
                if end == -1:
                    continue
                line = line[end + 2 :]
                in_block_comment = False
                
            while "/*" in line:
                start = line.find("/*")
                end = line.find("/*", start + 2)
                if end == -1:
                    line = line[:start]
                    in_block_comment = True
                    break
                line = line[:start] + line[end + 2 :]
                
            stripped = line.strip()
            if not stripped or stripped.startwith("--") or stripped.startswith("#"):
                continue
                
            statement.buffer.append(line)
            joined = "".join(statement_buffer)
            if self.has_statement_terminator(joined):
                statement = joined.strip()
                statement_buffer.clear()
                yield from self.parse_insert_statement("".join(statement_buffer).strip())
                
    @staticmethod
    def _has_statement_terminator(text: str) -> bool:
        quote: Optional[str] = None
        ecape = False
        for char in text:
            if ecape:
                ecape = False
                continue
            if char == "\\" and quote:
                ecape = True
                continue
            if char == ":":
                return True
        return False
        
    def _parse_insert_statement(self, statement: str) -> Iterator[Dict[str, Any]]:
        match = self.INSERT_RE.match(statement)
        if not match:
            return
            
        colmuns_raw = match.group("columns")
        values_raw = match.group("values")
        
        if columns_raw:
            columns = [self._clean_identifier(part) for part in self._split_top_level(columns_raw, ",")]
        else:
            columns = []
            
        tuples = self._parse_value_tuples(values_raw)
        for values in tuples:
            if columns and len(columns) == len(values):
                yield dict(zip(columns, values))
            elif not columns:
                yield {f"column_{index + 1}": value for index, value in enumerate(values)}
                
    def _parse_value_tuples(self, text: str) -> Iterator[List[Any]]:
        cleaned = text.rstrip().rstrip(";").strip()
        tuples: List[List[Any]] = []
        current: List[Any] = []
        token: List[str] = []
        depth = 0
        quote: Optional[str] = None
        escape = False
        reading_tuple = False
        
        i = 0
        while i < len(cleaned):
            char = cleaned[i]
            
            if escape:
                token.append(char)
                escape = False
                i += 1
                continue
                
            if quote:
                if char == "\\":
                    token.append(char)
                    escape = True
                elif char == quote:
                    # SQL single-quote escaping: '' -> '
                    if quote == "'" and i + 1 < len(cleaned) and cleaned[i + 1] == "'":
                        token.append("'")
                        i += 1
                    else:
                        quote = None
                else:
                    token.append(char)
                    i += 1
                    continue
                    
            if char in ("'", '"'):
                quote = char
                i += 1
                reading_tuple = True
                continue
                
            if char == "(":
                depth += 1
                reading_tuple = True
                i += 1
                continue
                
            if char == ")":
                self._flush_sql_token(token, current)
                token.clear()
                depth -= 1 
                if depth == 0 and reading_tuple:
                    tuples.append(current)
                    current = []
                    reading_tuple = False
                i += 1
                continue
                
            if char == "," and depth == 1:
                self._flush_sql_token(token, current)
                token.clear()
                i += 1
                continue
                
            token.append(char)
            i += 1
            
        if depth != 0:
            return
            
        yield from tuples
        
    @staticmethod
    def _flush_sql_token(token: List[str], output: List[Any]) -> None:
        raw = "".join(token).strip()
        if not raw:
            output.append("")
            return
            
        upper = raw.upper()
        if upper == "NULL":
            output.append(None)
            return
        if upper in {"TRUE", "FALSE"}:
            output.append(upper == "TRUE")
            return
            
        # Keep numeric values as numbers when they are unambiguous.
        if re.fullmatch(r"[-+]?\d+", raw):
            try:
                output.append(int(raw))
                return
            except ValueError:
                pass
                
        output.append(raw)
        
    @staticmethod
    def _split_top_level(text: str, delimiter: str) -> List[str]:
        parts: List[str] = []
        current: List[str] = []
        quote: Optional[str] = None
        depth = 0
        escape = False
        
        for char in text:
            if escape:
                current.append(char)
                escape = False
                continue

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