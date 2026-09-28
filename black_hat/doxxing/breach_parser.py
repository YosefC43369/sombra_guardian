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
            
        # Heuristic check for SQL if extension is ambiguous