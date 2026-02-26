"""
CSV parser for Groundhog radio traces.

Handles delimiter detection, encoding detection, and robust parsing.
"""
import csv
import io
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

ENCODINGS_TO_TRY = ["utf-8", "utf-8-sig", "latin-1", "cp1252", "iso-8859-1"]


def parse_csv(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse a CSV file containing Groundhog radio trace data.
    
    Features:
    - Auto-detect delimiter (comma, semicolon, tab, pipe)
    - Try multiple encodings
    - Skip empty rows
    
    Returns:
        List of dicts, one per row
    """
    import pandas as pd
    
    content = None
    used_encoding = None
    
    # Try encodings
    for enc in ENCODINGS_TO_TRY:
        try:
            with open(file_path, "r", encoding=enc) as f:
                content = f.read()
            used_encoding = enc
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    
    if content is None:
        raise ValueError(f"Could not read file with any encoding: {ENCODINGS_TO_TRY}")
    
    # Detect delimiter using csv.Sniffer
    delimiter = ","
    try:
        sample = content[:4096]
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
        logger.info(f"Detected delimiter: '{delimiter}'")
    except csv.Error:
        # Try to guess from first line
        first_line = content.split("\n")[0]
        for d in ["\t", ";", "|", ","]:
            if d in first_line:
                delimiter = d
                break
        logger.info(f"Sniffer failed, guessed delimiter: '{delimiter}'")
    
    # Parse with pandas
    try:
        df = pd.read_csv(
            io.StringIO(content),
            delimiter=delimiter,
            encoding=used_encoding,
            dtype=str,
            na_filter=False,
            skip_blank_lines=True,
        )
    except Exception as e:
        logger.error(f"Pandas CSV parse failed: {e}")
        raise ValueError(f"Failed to parse CSV: {e}")
    
    # Clean column names (strip whitespace)
    df.columns = [col.strip() for col in df.columns]
    
    result = df.to_dict(orient="records")
    logger.info(f"Parsed {len(result)} rows from CSV with {len(df.columns)} columns: {list(df.columns)}")
    return result
