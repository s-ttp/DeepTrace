"""
JSON parser for Groundhog radio traces.

Supports both list-of-events and nested export formats.
"""
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def parse_json(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse a JSON file containing Groundhog radio trace data.
    
    Strategies:
    1. Top-level list of objects → use directly
    2. Top-level object → discover the first list of dicts inside
    
    Returns:
        List of dicts, one per event
    """
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    
    # Strategy 1: Direct list
    if isinstance(data, list):
        if len(data) > 0 and isinstance(data[0], dict):
            logger.info(f"JSON contains direct list of {len(data)} events")
            return data
        elif len(data) == 0:
            logger.warning("JSON contains empty list")
            return []
        else:
            logger.warning(f"JSON list contains non-dict items: {type(data[0])}")
            return []
    
    # Strategy 2: Nested object - find the list
    if isinstance(data, dict):
        result = _find_event_list(data, max_depth=4)
        if result is not None:
            logger.info(f"Found event list with {len(result)} items in nested JSON")
            return result
    
    logger.warning("Could not find event list in JSON")
    return []


def _find_event_list(obj: Dict[str, Any], max_depth: int = 4, current_depth: int = 0) -> List[Dict[str, Any]]:
    """
    Recursively search for the first list of dicts in a nested structure.
    Prioritizes larger lists and keys that suggest event data.
    """
    if current_depth > max_depth:
        return None
    
    # Priority keys that suggest event data
    priority_keys = ["events", "data", "records", "rows", "results", "traces",
                     "measurements", "entries", "items", "logs"]
    
    best_list = None
    best_score = 0
    
    for key, value in obj.items():
        if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
            # Score based on key name matching + list length
            key_lower = key.lower()
            score = len(value)
            if key_lower in priority_keys:
                score += 10000  # Priority boost
            
            if score > best_score:
                best_score = score
                best_list = value
        
        elif isinstance(value, dict) and current_depth < max_depth:
            # Recurse into nested dicts
            nested = _find_event_list(value, max_depth, current_depth + 1)
            if nested is not None and len(nested) > (len(best_list) if best_list else 0):
                best_list = nested
    
    return best_list
