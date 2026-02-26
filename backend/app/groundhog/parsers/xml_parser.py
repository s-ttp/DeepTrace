"""
XML parser for Groundhog radio traces.

Extracts events from repeated XML elements.
"""
import logging
import xml.etree.ElementTree as ET
from collections import Counter
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def parse_xml(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse an XML file containing Groundhog radio trace data.
    
    Strategy:
    - Find the most-repeated child element tag
    - Extract attributes + child text values from each instance
    
    Returns:
        List of dicts, one per event/row
    """
    try:
        tree = ET.parse(file_path)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {e}")
    
    root = tree.getroot()
    
    # Strip namespaces for simpler processing
    _strip_namespace(root)
    
    # Find repeated elements at various depths
    best_tag, best_elements = _find_repeated_elements(root)
    
    if not best_elements:
        logger.warning("No repeated elements found in XML")
        return []
    
    logger.info(f"Found {len(best_elements)} repeated <{best_tag}> elements")
    
    # Convert elements to dicts
    result = []
    for elem in best_elements:
        row = _element_to_dict(elem)
        if row:
            result.append(row)
    
    logger.info(f"Extracted {len(result)} rows from XML")
    return result


def _strip_namespace(root):
    """Remove namespace prefixes from all tags."""
    for elem in root.iter():
        if "}" in elem.tag:
            elem.tag = elem.tag.split("}", 1)[1]


def _find_repeated_elements(root, max_depth=3) -> tuple:
    """
    Find the most-repeated child element tag (likely event rows).
    Returns (tag_name, list_of_elements).
    """
    # Count children at each level
    candidates = []
    
    def scan(element, depth=0):
        if depth > max_depth:
            return
        child_tags = Counter()
        for child in element:
            child_tags[child.tag] += 1
        
        for tag, count in child_tags.items():
            if count >= 2:  # At least 2 repetitions suggest data rows
                elements = list(element.iter(tag))
                # Direct children only for this parent
                direct = [c for c in element if c.tag == tag]
                candidates.append((tag, direct, count))
        
        for child in element:
            scan(child, depth + 1)
    
    scan(root)
    
    if not candidates:
        return None, []
    
    # Pick the candidate with the most repetitions
    best = max(candidates, key=lambda x: x[2])
    return best[0], best[1]


def _element_to_dict(elem) -> Dict[str, Any]:
    """Convert an XML element to a flat dictionary."""
    row = {}
    
    # Add attributes
    for key, value in elem.attrib.items():
        row[key] = value
    
    # Add text content of child elements
    for child in elem:
        tag = child.tag
        text = (child.text or "").strip()
        
        if text:
            row[tag] = text
        elif len(child) > 0:
            # Nested element - flatten with dot notation
            for subchild in child:
                sub_text = (subchild.text or "").strip()
                if sub_text:
                    row[f"{tag}.{subchild.tag}"] = sub_text
        
        # Also check attributes of child
        for attr_key, attr_val in child.attrib.items():
            row[f"{tag}.{attr_key}"] = attr_val
    
    # If element has direct text content
    if elem.text and elem.text.strip():
        row["_text"] = elem.text.strip()
    
    return row
