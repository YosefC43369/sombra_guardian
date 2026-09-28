import os
import json
import csv
import sqlite3
import gzip
import bz2
import logging
from typing import Generator, Dict, Any, Optional, List
from io import StringIO, BytesIO
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [PARSER] - %(message)s')
logger = logging.getLogger(__name__)

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