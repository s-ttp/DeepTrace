"""
HTML parser for Groundhog radio traces.

Extracts data from HTML tables and embedded JSON blobs in <script> tags.
Uses BeautifulSoup for robust HTML parsing.
"""
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def parse_html(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse an HTML file containing Groundhog radio trace data.
    
    Strategy:
    1. Look for embedded JSON in <script> tags first
    2. Fall back to HTML table extraction
    
    Returns:
        List of dicts, one per row/event
    """
    from bs4 import BeautifulSoup
    
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    
    soup = BeautifulSoup(content, "html.parser")
    
    # Strategy 1: Check for embedded JSON in <script> tags
    for script in soup.find_all("script"):
        text = script.get_text(strip=True)
        if not text:
            continue
        # Try to find JSON arrays or objects
        for start_char, end_char in [("[", "]"), ("{", "}")]:
            idx_start = text.find(start_char)
            if idx_start >= 0:
                # Find matching end
                idx_end = text.rfind(end_char)
                if idx_end > idx_start:
                    candidate = text[idx_start:idx_end + 1]
                    try:
                        data = json.loads(candidate)
                        if isinstance(data, list) and len(data) > 0:
                            logger.info(f"Found embedded JSON array with {len(data)} items in <script>")
                            if isinstance(data[0], dict):
                                return data
                        elif isinstance(data, dict):
                            # Try to find a list inside the dict
                            for key, val in data.items():
                                if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                                    logger.info(f"Found embedded JSON list under key '{key}' with {len(val)} items")
                                    return val
                    except (json.JSONDecodeError, IndexError):
                        continue
    
    # Strategy 2: Extract from HTML tables
    tables = soup.find_all("table")
    if tables:
        # Use the largest table (most rows)
        best_table = max(tables, key=lambda t: len(t.find_all("tr")))
        rows = best_table.find_all("tr")
        if len(rows) >= 2:
            header_row = rows[0]
            headers = [cell.get_text(strip=True) for cell in header_row.find_all(["th", "td"])]
            
            if headers:
                result = []
                for row in rows[1:]:
                    cells = row.find_all(["td", "th"])
                    if len(cells) == len(headers):
                        row_dict = {}
                        for i, cell in enumerate(cells):
                            row_dict[headers[i]] = cell.get_text(strip=True)
                        result.append(row_dict)
                if result:
                    logger.info(f"Extracted {len(result)} rows from HTML table")
                    return result
                    
    # Strategy 3: Groundhog sequence diagram format (A->B: {"type":"event", "url":"..."})
    import re
    from urllib.parse import unquote_plus
    
    logger.info("Attempting Strategy 3: js-sequence-diagrams parsing")
    result = []
    current_time = None
    
    # Very fast raw text scan for JSON structures at the end of lines
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if not line.endswith("}"):
            continue
            
        # Extract the JSON payload at the end of the line
        json_start = line.find("{")
        if json_start == -1:
            continue
            
        payload_str = line[json_start:]
        try:
            payload = json.loads(payload_str)
        except json.JSONDecodeError:
            continue
            
        if payload.get("type") == "datetime":
            current_time = payload.get("message")
        elif payload.get("type") == "event":
            prefix = line[:json_start].strip()
            from_node, to_node = None, None
            if "->" in prefix:
                parts = prefix.rstrip(":").split("->")
                if len(parts) == 2:
                    from_node = parts[0].strip("\"' ")
                    to_node = parts[1].strip("\"' ")
                    
            event_dict = {
                "Time": current_time,
                "Message": payload.get("message", "Unknown"),
                "from_node": from_node,
                "to_node": to_node
            }
            
            # Extract KPI data from the url-encoded javascript call
            url_str = payload.get("url", "")
            if "updateEventMessage" in url_str:
                # Extract the string inside ('...')
                encoded_match = re.search(r"updateEventMessage\('([^']+)'\)", url_str)
                if encoded_match:
                    raw_decoded = unquote_plus(encoded_match.group(1)).replace('\\n', ' ')
                    
                    # Also look for explicit S1AP release cause:
                    cause_match = re.search(r"<Cause>\s*<radioNetwork>([^<]+)</radioNetwork>\s*</Cause>", raw_decoded, re.IGNORECASE)
                    if cause_match:
                        event_dict["release_cause"] = cause_match.group(1)
                        
                    # Extract XML-like <key>value</key> pairs
                    tags = re.finditer(r"<([^>]+)>([^<]*)</\1>", raw_decoded)
                    for tag in tags:
                        key = tag.group(1).strip()
                        val = tag.group(2).strip()
                        if key and key.lower() not in ["internal", "msg"]:
                            event_dict[key] = val
                            
            result.append(event_dict)
            
    if result:
        logger.info(f"Extracted {len(result)} events from sequence diagram text")
        return result
        
    logger.warning("All strategies failed to extract data from HTML file")
    return []

