"""
Vendor-Specific Code Mapper

Handles proprietary reason codes from:
- Nokia MSS (X.int format)
- Huawei IMS (proprietary text patterns)
"""
import json
import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Load vendor mappings from JSON file
VENDOR_MAPPINGS_FILE = Path(__file__).parent / "vendor_mappings.json"
_vendor_mappings: Dict[str, Any] = {}


def load_vendor_mappings() -> Dict[str, Any]:
    """Load vendor mappings from JSON file"""
    global _vendor_mappings
    
    if _vendor_mappings:
        return _vendor_mappings
    
    if VENDOR_MAPPINGS_FILE.exists():
        try:
            with open(VENDOR_MAPPINGS_FILE, "r") as f:
                _vendor_mappings = json.load(f)
                logger.info(f"Loaded vendor mappings from {VENDOR_MAPPINGS_FILE}")
        except Exception as e:
            logger.warning(f"Failed to load vendor mappings: {e}")
            _vendor_mappings = {}
    
    return _vendor_mappings


def get_nokia_code_label(reasoncode: str) -> Optional[str]:
    """
    Map Nokia X.int reasoncode to human-readable label.
    
    Args:
        reasoncode: Hex string like "0x00000000"
    
    Returns:
        Label or None if unmapped
    """
    mappings = load_vendor_mappings()
    x_int = mappings.get("X.int", {})
    codes = x_int.get("codes", {})
    
    # Normalize hex format
    code_normalized = reasoncode.lower()
    if not code_normalized.startswith("0x"):
        code_normalized = f"0x{code_normalized}"
    
    return codes.get(code_normalized) or codes.get(reasoncode)


def get_huawei_pattern_info(text: str) -> Optional[Dict[str, str]]:
    """
    Match Huawei proprietary text pattern.
    
    Args:
        text: Text from SIP Reason header
    
    Returns:
        Dict with component and meaning, or None
    """
    mappings = load_vendor_mappings()
    patterns = mappings.get("huawei_text_patterns", {})
    
    text_lower = text.lower()
    for pattern, info in patterns.items():
        if pattern.startswith("_"):  # Skip meta fields
            continue
        if pattern.lower() in text_lower:
            return {
                "pattern": pattern,
                "component": info.get("component", "Unknown"),
                "meaning": info.get("meaning", "Unknown")
            }
    
    return None


def map_vendor_reason(reason_parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich parsed reason with vendor-specific mappings.
    
    Args:
        reason_parsed: Output from parse_reason_header()
    
    Returns:
        Enriched dict with vendor label and info
    """
    result = reason_parsed.copy()
    
    if not result.get("is_vendor_specific"):
        return result
    
    protocol = result.get("protocol", "")
    
    # Nokia X.int
    if protocol.startswith("X."):
        cause = result.get("cause")
        if cause:
            label = get_nokia_code_label(cause)
            if label:
                result["vendor_label"] = label
            else:
                result["vendor_label"] = f"Nokia {protocol} code {cause}"
    
    # Huawei text patterns
    text = result.get("text")
    if text:
        huawei_info = get_huawei_pattern_info(text)
        if huawei_info:
            result["vendor_info"] = huawei_info
            result["vendor_label"] = f"Huawei {huawei_info['component']}: {huawei_info['meaning']}"
    
    return result


def format_vendor_reason_for_display(reason_parsed: Dict[str, Any]) -> str:
    """
    Format vendor reason for human-readable display.
    
    Args:
        reason_parsed: Enriched parsed reason
    
    Returns:
        Human-readable string
    """
    enriched = map_vendor_reason(reason_parsed)
    
    if enriched.get("vendor_label"):
        return enriched["vendor_label"]
    
    if enriched.get("is_vendor_specific"):
        protocol = enriched.get("protocol", "Vendor")
        cause = enriched.get("cause", "unknown")
        return f"{protocol} (code: {cause}) - Vendor-specific, see documentation"
    
    # Standard format
    protocol = enriched.get("protocol", "SIP")
    cause = enriched.get("cause", "")
    text = enriched.get("text", "")
    
    if text:
        return f"{protocol} {cause}: {text}"
    elif cause:
        return f"{protocol} cause={cause}"
    
    return "Unknown reason"
