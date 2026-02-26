"""
Groundhog Radio Trace Ingestion Orchestrator.

Detects file format, dispatches to the correct parser,
normalizes events, and saves artifacts.
"""
import os
import json
import shutil
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from .normalize import normalize_rows
from .summary import generate_summary, save_summary

logger = logging.getLogger(__name__)

# Supported extensions → parser function
FORMAT_MAP = {
    ".html": "html",
    ".htm": "html",
    ".csv": "csv",
    ".xls": "xls",
    ".xlsx": "xls",
    ".json": "json",
    ".xml": "xml",
}


def detect_format(file_path: str) -> str:
    """Detect file format from extension."""
    ext = os.path.splitext(file_path)[1].lower()
    fmt = FORMAT_MAP.get(ext)
    if not fmt:
        raise ValueError(
            f"Unsupported file format: '{ext}'. "
            f"Supported formats: {list(FORMAT_MAP.keys())}"
        )
    return fmt


def _get_parser(fmt: str):
    """Import and return the parser function for the given format."""
    if fmt == "html":
        from .parsers.html_parser import parse_html
        return parse_html
    elif fmt == "csv":
        from .parsers.csv_parser import parse_csv
        return parse_csv
    elif fmt == "xls":
        from .parsers.xls_parser import parse_xls
        return parse_xls
    elif fmt == "json":
        from .parsers.json_parser import parse_json
        return parse_json
    elif fmt == "xml":
        from .parsers.xml_parser import parse_xml
        return parse_xml
    else:
        raise ValueError(f"No parser available for format: {fmt}")


def ingest_groundhog(
    file_path: str,
    output_dir: str = None,
    timezone: str = None,
) -> Dict[str, Any]:
    """
    Main entry point for Groundhog radio trace ingestion.
    
    Args:
        file_path: Path to the Groundhog trace file
        output_dir: Directory to save artifacts (normalized events + summary)
        timezone: Timezone override (default: Asia/Qatar)
        
    Returns:
        Dict with:
        - events: list of normalized radio events
        - summary: summary statistics dict
        - format: detected file format
        - column_mapping: how columns were mapped
        - unmapped_columns: columns not recognized
    """
    # 1. Detect format
    fmt = detect_format(file_path)
    logger.info(f"Detected format: {fmt} for file {file_path}")
    
    # 2. Parse raw rows
    parser = _get_parser(fmt)
    try:
        raw_rows = parser(file_path)
    except Exception as e:
        logger.error(f"Parser failed for {fmt}: {e}")
        raise ValueError(f"Failed to parse {fmt} file: {e}")
    
    if not raw_rows:
        raise ValueError("No data rows found in the file")
    
    logger.info(f"Parsed {len(raw_rows)} raw rows")
    
    # 3. Normalize
    try:
        events, col_mapping, unmapped = normalize_rows(raw_rows, timezone=timezone)
    except ValueError as e:
        # Re-raise with column info for user-friendly error
        raise
    
    if not events:
        raise ValueError("No valid events after normalization (all timestamp parsing failed)")
    
    # 4. Generate summary
    summary = generate_summary(events)
    
    # 5. Save artifacts if output_dir provided
    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        
        # Copy source file
        src_dest = out_path / f"source{os.path.splitext(file_path)[1]}"
        shutil.copy2(file_path, src_dest)
        
        # Save normalized events
        events_path = out_path / "normalized_radio_events.json"
        with open(events_path, "w") as f:
            json.dump(events, f, indent=2, default=str)
        logger.info(f"Saved {len(events)} normalized events to {events_path}")
        
        # Save summary
        save_summary(summary, str(out_path / "groundhog_summary.json"))
    
    return {
        "events": events,
        "summary": summary,
        "format": fmt,
        "column_mapping": col_mapping,
        "unmapped_columns": unmapped,
    }
