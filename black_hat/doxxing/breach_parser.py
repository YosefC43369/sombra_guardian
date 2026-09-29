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
                
            if quote:
                current.append(char)
                if char == "\\":
                    escape = True
                elif char == quote:
                    quote = None
                continue
                
            if char in ("'", '"', "`"):
                quote = char
                current.append(char)
                continue
            if char == "(":
                depth += 1
                current.append(char)
                continue
            if char == ")":
                depth = max(0, depth - 1)
                current.append(char)
                continue
            if char == delimiter and depth == 0:
                parts.append("".join(current).strip())
                current.clear()
                continue
            current.append(char)
            
        parts.append("".join(current).strip())
                 return parts
                
# -------- JSON streaming parser --------

class JSONStreamParser:
    """Stream JSON Lines and ordinary JSON arrays/objects."""
    
    def __init__(self, config: ParserConfig) -> None:
        self.config = config
    
    def parse(self, stream: TextIO, logical_format: str) -> Iterator[Any]:
        if logical_format = "jsonl":
            yield from self.parse_jsonl(stream)
            return
        yield from self.parse_json_document(stream)
        
    def parse_jsonl(self, stream: TextIO) -> Iterator[ANY]:
        line_number = 0
        for raw_line in stream:
            line_number = 0
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            try:
                 yield json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSONL record at line %d", line_number)
                
    def parse_json_document(self, stream: TextIO) -> Iterator[Any]:
        decoder = json.JSONDecoder()
        buffer = ""
        eof = False
        
        while not eof or buffer.strip():
            if not eof and len(buffer) < 1024 * 1024:
                chunk = stream.read(256 * 1024)
                if chunk:
                    buffer += chunk
                else:
                    eof = True
                    
            stripped = buffer.lstrip("\ufeff \t\r\n")
            consumed_prefix = len(buffer) - len(stripped)
            buffer = stripped
            if not buffer:
                if eof:
                    break
                continue
                
            try:
                value, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if eof:
                    # Fallback to one final whole-buffer parse for useful errors.
                    try:
                        value = json.loads(buffer)
                         end = len(buffer)
                    except json.JSONDecodeError:
                        logger.warning("Unable to parse JSON document")
                        break
                else:
                     # Need more bytes to complete the document.
                     chunk = stream.read(256 * 1024)
                      if chunk:
                        buffer += chunk
                        continue
                      eof = True
                      continue
                    
            buffer = buffer[end:]
            if isinstance(value, list):
                if self.config.json_array_key and self.config.json_array_key in value:
                    nested = value[self.config.json_array_key]
                    if isinstance(nested, list):
                        yield from self._iter_json_container(nested)
                    else:
                        yield value
                else:
                    yield value
            else:
                yield value
                
    @staticmethod
    def _iter_json_container(container: Sequence[Any]) -> Iterator[Any]:
        for item in container:
            yield item
            

# -------- CSV / text parser --------

class DelimitedParser:
    """Parse CSV, TSV, or delimited text."""
    
    def __init__(self, config: ParserConfig) -> None:
        self.config = config
        
    def parse(self, stream: TextIO, logical_format: str) -> Iterator[Dict[str, Any]]:
        delimiter = self._detect_delimiter(stream, logical_format)
        try:
            reader = csv.DictReader(
                stream,
                delimiter=delimiter,
                quotechar=self.config.csv_quotechar,
                restkey="_extra_fields",
                restval="",
            )
            if not reader.fieldnames:
                return
                
            for row in reader:
                yield dict(row)
        except csv.Error as exc:
            raise ParserError(f"CSV parser error: {exc}") from exc
            
    def _detect_delimiter(self, stream: TextIO, logical_format: str) -> str:
        if self.config.csv_delimiter:
            return self.config.csv_delimiter
        if logical_format == "tsv":
            return "\t"
        if logical_format == "csv":
            return ","
            
        # For generic text, peek from the stream if seekable.
        try:
            position = stream.tell()
            sample = stream.read(8192)
            stream.seek(position)
        except (OSError, AttributeError):
            return ","
            
        try:
            dialect = csv.Sniffer().sniff(sample, delimiter=",\t;|")
            return dialect.delimiter
        except csv.Error:
            return ","


# -------- Main Parser --------

class BreachParser:
    """
    Extended parser pipeline.

    The original public methods are retained where practical:
        detect_format()
        open_stream()
        parse_csv()
        parse_json()
        parse_sql()
        parse_file()
        process_directory()
    """
    
    SUPPORTED_LOGICAL_FORMATS = {"csv", "tsv", "text", "json", "jsonl", "sql"}
    SUPPORTED_EXTENSIONS =  {
        ".txt", ".log", ".csv", ".tsv", ".sql", ".json", ".jsonl", ".ndjson",
        ".gz", ".bz2", ".xz",
        ".csv.gz", ".tsv.gz", ".json.gz", ".jsonl.gz", ".sql.gz",
        ".csv.bz2", ".json.bz2", ".sql.bz2",
        ".csv.xz", ".json.xz", ".sql.xz",
    }

    def __init__(self, chunk_size: int = 500, config: Optional[ParserConfig] = None) -> None:
        """
        Initialize the BreachParser.
        :param chunk_size: Number of records to yield before sending to indexer.
        """
        if config is None:
            config = ParserConfig(chunk_size=chunk_size)
        elif config.chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
            
        self.config = config
        self.stats = ParserStats()
        self.detector = FormatDetector(config.encoding)
        self.normalizer = RecordNormalizer(config, self.stats)
        self.sql_parser = SQLInsertParser(config.sql_case_sensitive)
        self.json_parser = JSONStreamParser(config)
        self.delimited_parser = DelimitedParser(config)
        self._seen_hashes: set[str] = set()
        self._start_time = time.monotonic()
        
    def detect_format(self, file_path: str) -> str:
        """Detect file format based in extension and content."""
        logical_format, _codec = self.detector.detect(Path(file_path))
        return logical_format
        
    def open_stream(self, file_path: str) -> TextIO:
        """Open file stream handling compression."""
        logical_format, codec = self.detector.detect(Path(file_path))
        _ = logical_format
        return self.detector._open_text(Path(file_path), codec)
            
    def parse_csv(self, stream: TextIO) -> Iterator[Dict[str, Any]]:
        """Parse CSV/TSV files."""
        yield from self.delimited_parser.parse(stream, "csv")
            
    def parse_json(self, stream: TextIO) -> Iterator[Any]:
        """Parse JSON (array or JSONL)."""
        yield from self.json_parser.parse(stream, "json")
                        
    def parse_sql(self, stream: TextIO) -> Iterator[Dict[str, Any]]:
        """
        Simple SQL INSERT parser.
        Assumes format: INSERT INTO table (col1, col2) VALUES ('val1', 'val2');
        """
        yield from self.sql_parser.parse_stream(stream)
        
    def _check_file(self, path: Path) -> Optional[str]:
        if not path.exists():
            return "file does not exist"
        if not path.is_file():
            return "path is not a regular file"
            
        if self.config.max_file_size is not None:
            size = path.stat().st_size
            if size > self.config.max_file_size:
                return f"file exceeds max_file_size ({size} > {self.config.max_file_size})"
        return None
        
    def _iter_records(self, stream: TextIO, logical_format: str) -> Iterator[Any]:
        if logical_format in {"csv", "tsv", "text"}:
            yield from self.delimited_parser.parse(stream, logical_format)
        elif logical_format in {"json", "jsonl"}:
            yield from self.json_parser.parse(stream, logical_format)
        elif logical_format == "sql":
            yield from self.sql_parser.parse_stream(stream)
        else:
            raise UnsupportedFormatError(logical_format)
            
    def _prepare_record(self, record: Any, source_file: str, parsed_at: str, ordinal: int) -> Optional[Dict[str, Any]]:
        normalized = self.normalizer.normalize_record(record)
        if normalized is None:
            return None
            
        # Compute the content hash before adding parser metadata so that the
        # same logical record appearing in different files can be deduplicated.
        content_digest = record_hash(normalized, self.config.hash_algorithm)
        if self.config.deduplicate:
            if content_digest in self._seen_hashes:
                self.stats.records_deduplicated += 1
                return None
            self._seen_hashes.add(content_digest)
            
        normalized["_source_file"] = source_file
        normalized["_parsed_at"] = parsed_at
        normalized["_record_number"] = ordinal
        normalized["_record_hash"] = content_digest
        return normalized
        
    def parse_file(self, file_path: str) -> Iterator[List[Dict[str, Any]]:
        """Parse a single file and yield normalized records in chunks."""
        path = Path(file_path)
        self.stats.files_seen += 1
        error = self._check_file(path)
        if error:
            logger.warning("Skipping %s: %s", path, error)
            self.stats.files_skipped += 1
            return
            
        started = time.monotonic()
        try:
            logical_format, codec = self.detector.detect(path)
            self.stats.by_format[logical_format] += 1
            logger.info("Parsing %s as %s%s", path, logical_format, f" via {codec}" if codec else "")
            
            parsed_at = utc_now()
            ordinal = 0
            chunk: List[Dict[str, Any]] = []
            try:
                self.stats.bytes_read += path.stat().st_size
            except OSError:
                pass
                
            with self.detector._open_text(path, codec) as stream:
                for raw_record in self._iter_records(stream, logical_format):
                    self.stats.records_read += 1
                    ordinal += 1
                    if self.config.max_records_per_file and ordinal > self.config.max_records_per_file:
                        logger.info("Record limit reached for %s", path)
                        break
                    
                    record = self._prepare_record(
                        raw_record,
                         source_file=path.name,
                         parsed_at=parsed_at,
                         ordinal=ordinal,
                    )
                    if record is None:
                        continue
                        
                    self.stats.records_emitted += 1
                    chunk.append(record)
                    
                    if len(chunk) >= self.config.chunk_size:
                        yield chunk
                        chunk = []
                        
                if chunk:
                    yield chunk
                    
            self.stats.files_parsed += 1
            logger.info(
                "Finished %s: %d records read, %d emitted in %.2fs",
                patch,
                ordinal,
                self.stats.records_emitted,
                time.monotonic() - started,
            )
            
        except (OSError, UnicodeError, ParserError, csv.Error) as exc:
            self.stats.files_failed += 1
            self.stats.errors.append(f"{path}: unexpected error: {exc}")
            logger.exception("Unexpected error parsing %s", path)
            
    def process_directory(
        self,
        directory: str,
        recursive: bool = True,
        include_extensions: Optional[Iterable[str]] = None,
        exclude_names: Optional[Iterable[str]] = None,
    ) -> Iterator[List[Dict[str, Any]]]:
        """Recursively scan a directory and yield chunks from supported files."""
        root = Patch(directory)
        if not root.exists() or not root.is_dir():
            raise NotADirectoryError(directory)
            
        include = {ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in (include_extensions or [])}
        excludes = set(exclude_names or [])
        
        iterator = root.rglob("*") if recursive else root.glob("*")
        for path in sorted(iterator):
            if not path.is_file():
                continue
            if path.name in excludes:
                continue
            if include and not self._has_supported_extension(path, include):
                continue
            if not include and not self._has_supported_extension(path, self.SUPPORTED_EXTENSIONS):
                continue
                
            yield from self.parse_file(str(path))
            
        self.stats.elapsed_seconds = time.monotonic() - self._start_time
        
    @staticmethod
    def _has_supported_extension(path: Path, extensions: Iterable[str]) -> bool:
        name = path.name.lower()
        return any(name.endswith(ext.lower()) for ext in extensions)
        
    def finalize(self) -> ParseStats:
        self.stats.elapsed.seconds = time.monotonic() - self._start_time
        return self.stats
        
        
# -------- SQLite sink --------

class SQLiteSink:
    """Persist normalized records in a local SQLite database."""
    
    def __init__(self, database_path: str, batch_size: int = 1000) -> None:
        self.database_path = Path(database_path)
        self.batch_size = max(1, batch_size)
        self.connection: Optional[sqlite3.Connection] = None
        self._pending = 0
        
    def open(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.database_path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema()
        
    def _create_schema(self) -> None:
        assert self.connection is not None
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_hash TEXT,
                source_file TEXT NOT NULL,
                parsed_at TEXT NOT NULL,
                record_number INTEGER,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_manifest (
                source_file TEXT PRIMARY KEY,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_records_source_file
                ON records(source_file);

            CREATE INDEX IF NOT EXISTS idx_records_hash
                ON records(record_hash);
            """
        )
        self.connection.commit()
        
    def write_chunk(self, records: Sequence[Dict[str, Any]]) -> int:
        if not records:
            return 0
        if self.connection is None:
            raise RuntimeError("SQLiteSink is not open")
            
        rows = []
        for record in records:
            rows.append(
                (
                    record.get("_record_hash"),
                    str(record.get("_source_file", "")),
                    str(record.get("_parsed_at", "")),
                    int(record.get("_record_number", 0)),
                    canonical_json(record),
                )
            )
            
        self.connection.executemany(
            """
            INSERT INTO records (
                record_hash, source_file, parsed_at, record_number, payload_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            rows,
        )
        self._pending += len(rows)
        
        if self._pending >= self.batch_size:
            self.connection.commit()
            self._pending = 0
        return len(rows)
        
    def write_manifest(self, path: Path, digest: str) -> None:
        if self.connection is None:
            raise RuntimeError("SQLiteSink is not open")
        stat = path.stat()
        self.connection.execute(
            """
            INSERT INTO file_manifest (source_file, size_bytes, sha256, last_seen_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source_file) DO UPDATE SET
                size_bytes=excluded.size_bytes,
                sha256=excluded.sha256,
                last_seen_at=excluded.last_seen_at
            """,
            (str(path), stat.st_size, digest, utc_now()),
        )
        
    def close(self) -> None:
        if self.connection is not None:
            self.connection.commit()
            self.connection.close()
            self.connection = None
            self._pending = 0
            
    def __enter__(self) -> "SQLiteSink":
        self.open()
        return self
        
    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
        
        
# -------- JSONL sink --------

class JSONLSink:
    """Write normalized records as line-delimited JSON."""

    def __init__(self, output_path: str) -> None:
        self.output_path = Path(output_path)
        self.handle: Optional[TextIO] = None

    def open(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.output_path.open("w", encoding="utf-8", newline="\n")

    def write_chunk(self, records: Sequence[Dict[str, Any]]) -> int:
        if self.handle is None:
            raise RuntimeError("JSONLSink is not open")
        for record in records:
            self.handle.write(canonical_json(record))
            self.handle.write("\n")
        self.handle.flush()
        return len(records)

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def __enter__(self) -> "JSONLSink":
        self.open()
        return self
        
    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
        
        
# -------- File discovery / manifest --------


@dataclass
class FileInfo:
    path: Path
    size_bytes: int
    modified_at: float
    sha256: Optional[str] = None
    
    
class FileScanner:
    def __init__(
        self,
        extensions: Iterable[str],
        max_file_size: Optional[int] = None,
        excluded_paths: Optional[Iterable[Path]] = None,
    ) -> None:
        self.extensions = {x.lower() if x.startswith(".") else f".{x.lower()}" for x in extensions}
        self.max_file_size = max_file_size
        self.excluded_paths = {Path(p).resolve() for p in (excluded_paths or [])}
        
    def scan(self, root: Path, recursive: bool = True) -> Iterator[FileInfo]:
        if not root.exists():
            raise FileNotFoundError(root)
        if root.is_file():
            candidates = [root]
        elif recursive:
            candidates = root.rglob("*")
        else:
            candidates = root.glob("*")
            
        for path in sorted(candidates):
            if not path.is_file():
                continue
            try:
                if path.resolve() in self.excluded_paths:
                    continue
            except OSError:
                pass
            if self.extensions and not any(path.name.lower().endswith(ext) for ext in self.extensions):
                continue
            stat = path.stat()
            if self.max_file_size is not None and stat.st_size > self.max_file_size:
                logger.warning("Skipping oversized file: %s", path)
                continue
            yield FileInfo(path=path, size_bytes=stat.st_size, modified_at=stat.st_mtime)
            
            
# -------- Batch engine --------

class BatchEngine:
    """Connect file discovery, parser and one or more local sinks."""

    def __init__(
        self,
        parser: BreachParser,
        sqlite_sink: Optional[SQLiteSink] = None,
        jsonl_sink: Optional[JSONLSink] = None,
    ) -> None:
        self.parser = parser
        self.sqlite_sink = sqlite_sink
        self.jsonl_sink = jsonl_sink

    def run(
        self,
        input_path: str,
        recursive: bool = True,
        excluded_paths: Optional[Iterable[Path]] = None,
    ) -> ParseStats:
        root = Path(input_path)
        started = time.monotonic()

        if self.sqlite_sink:
            self.sqlite_sink.open()
        if self.jsonl_sink:
            self.jsonl_sink.open()

        try:
            if root.is_file():
                files = [FileInfo(root, root.stat().st_size, root.stat().st_mtime)]
            else:
                 scanner = FileScanner(
                    BreachParser.SUPPORTED_EXTENSIONS,
                    self.parser.config.max_file_size,
                    excluded_paths=excluded_paths,
                )
                files = scanner.scan(root, recursive=recursive)

            for info in files:
                logger.info("Queueing file: %s", info.path)
                digest: Optional[str] = None
                if self.sqlite_sink:
                    try:
                        digest = calculate_file_hash(info.path, "sha256")
                    except OSError as exc:
                        logger.warning("Unable to hash %s: %s", info.path, exc)

                for chunk in self.parser.parse_file(str(info.path)):
                    if self.sqlite_sink:
                        self.sqlite_sink.write_chunk(chunk)
                    if self.jsonl_sink:
                        self.jsonl_sink.write_chunk(chunk)

                if self.sqlite_sink and digest:
                    try:
                        self.sqlite_sink.write_manifest(info.path, digest)
                         self.sqlite_sink.connection.commit()
                    except OSError as exc:
                         logger.warning("Unable to update manifest for %s: %s", info.path, exc)

        finally:
            if self.sqlite_sink:
                self.sqlite_sink.close()
            if self.jsonl_sink:
                self.jsonl_sink.close()

        self.parser.stats.elapsed_seconds = time.monotonic() - started
        return self.parser.finalize()
        

# -------- CLI --------

def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return number
    
    
def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline local parser for CSV/JSON/JSONL/SQL datasets."
    )
    parser.add_argument("--input", required=True, help="Input file or directory")
    parser.add_argument("--output-db", help="SQLite output database")
    parser.add_argument("--output-jsonl", help="Normalized JSONL output file")