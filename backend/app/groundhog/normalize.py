"""
Column normalization and mapping for Groundhog radio traces.

Maps various column names from different Groundhog export formats
to the unified normalized radio event schema.
"""
import re
import logging
from typing import List, Dict, Any, Optional, Tuple

from .schema import make_radio_event, GENERATION_HINTS, EVENT_TYPES
from .timezone import parse_timestamp

logger = logging.getLogger(__name__)

# Synonym map: normalized field → list of known column names (case-insensitive)
COLUMN_SYNONYMS = {
    "timestamp": [
        "time", "timestamp", "datetime", "event time", "event_time",
        "date time", "date_time", "time_stamp", "ts", "epoch",
        "frame.time_epoch", "start time", "start_time", "event timestamp",
    ],
    "event_type": [
        "event", "type", "event type", "event_type", "message",
        "procedure", "message type", "msg_type", "event name",
        "event_name", "procedure_name", "event_category",
    ],
    "event_label": [
        "event label", "label", "description", "event description",
        "summary", "event_label", "detail", "info",
    ],
    "generation": [
        "generation", "gen", "network_type", "network type",
        "technology", "tech", "network_gen",
    ],
    "rat": [
        "rat", "rat_type", "access technology", "access_technology",
        "radio access", "radio_access_type",
    ],
    "cell_id": [
        "cell id", "cell_id", "cellid", "eci", "cgi", "ci",
        "cell identity", "cell_identity", "global cell id",
        "e-utran cell id", "nr cell id",
    ],
    "tac": [
        "tac", "tracking area code", "tracking_area_code", "lac",
        "location area code", "la",
    ],
    "pci": [
        "pci", "physical cell id", "physical_cell_id", "phy cell id",
        "physical cell identity",
    ],
    "earfcn": [
        "earfcn", "arfcn", "e-utra arfcn", "dl earfcn",
        "dl_earfcn", "frequency",
    ],
    "nrarfcn": [
        "nrarfcn", "nr arfcn", "nr_arfcn", "ssb arfcn",
    ],
    "imsi": [
        "imsi", "subscriber id", "subscriber_id",
    ],
    "guti": [
        "guti", "5g-guti", "4g-guti", "s-tmsi",
    ],
    "tmsi": [
        "tmsi", "m-tmsi", "p-tmsi",
    ],
    "ue_ip": [
        "ue ip", "ue_ip", "ue ip address", "pdn address",
        "ip address", "ip_address",
    ],
    "rsrp": [
        "rsrp", "rsrp(dbm)", "rsrp (dbm)", "rsrp_dbm",
        "serving rsrp", "serving_rsrp",
    ],
    "rsrq": [
        "rsrq", "rsrq(db)", "rsrq (db)", "rsrq_db",
        "serving rsrq", "serving_rsrq",
    ],
    "sinr": [
        "sinr", "sinr(db)", "sinr (db)", "sinr_db",
        "rs-sinr", "rs_sinr", "snr",
    ],
    "cqi": [
        "cqi", "channel quality", "channel_quality_indicator",
    ],
    "ta": [
        "ta", "timing advance", "timing_advance",
    ],
    "dl_bler": [
        "dl bler", "dl_bler", "bler dl", "dl block error rate",
    ],
    "ul_bler": [
        "ul bler", "ul_bler", "bler ul", "ul block error rate",
    ],
    "throughput_dl_kbps": [
        "dl throughput", "dl_throughput", "throughput dl",
        "dl throughput(kbps)", "dl_throughput_kbps",
        "dl data rate", "pdcp dl throughput",
    ],
    "throughput_ul_kbps": [
        "ul throughput", "ul_throughput", "throughput ul",
        "ul throughput(kbps)", "ul_throughput_kbps",
        "ul data rate", "pdcp ul throughput",
    ],
}

# Build reverse lookup: lowercase synonym → normalized field
_REVERSE_MAP = {}
for field, synonyms in COLUMN_SYNONYMS.items():
    for syn in synonyms:
        _REVERSE_MAP[syn.lower()] = field


def map_columns(raw_columns: List[str]) -> Tuple[Dict[str, str], List[str]]:
    """
    Map raw column names to normalized field names.
    
    Returns:
        Tuple of (mapping dict {raw_col → normalized_field}, unmapped columns list)
    """
    mapping = {}
    unmapped = []
    
    for col in raw_columns:
        col_clean = col.strip()
        col_lower = col_clean.lower()
        
        if col_lower in _REVERSE_MAP:
            mapping[col_clean] = _REVERSE_MAP[col_lower]
        else:
            # Try partial matching
            matched = False
            for syn, field in _REVERSE_MAP.items():
                if syn in col_lower or col_lower in syn:
                    mapping[col_clean] = field
                    matched = True
                    break
            if not matched:
                unmapped.append(col_clean)
    
    return mapping, unmapped


def normalize_rows(
    rows: List[Dict[str, Any]],
    timezone: str = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, str], List[str]]:
    """
    Normalize raw parsed rows into the unified radio event schema.
    
    Args:
        rows: Raw parsed rows (dicts with original column names)
        timezone: Timezone override
        
    Returns:
        Tuple of (normalized_events, column_mapping, unmapped_columns)
        
    Raises:
        ValueError: If no timestamp column is found
    """
    if not rows:
        return [], {}, []
    
    # Map columns
    raw_columns = list(rows[0].keys())
    col_map, unmapped = map_columns(raw_columns)
    
    logger.info(f"Column mapping: {col_map}")
    if unmapped:
        logger.info(f"Unmapped columns (stored in raw): {unmapped}")
    
    # Check for timestamp column
    ts_cols = [raw_col for raw_col, norm_field in col_map.items() if norm_field == "timestamp"]
    if not ts_cols:
        detected = list(rows[0].keys())
        raise ValueError(
            f"No timestamp column found in data. "
            f"Detected columns: {detected}. "
            f"Expected one of: {COLUMN_SYNONYMS['timestamp']}"
        )
    
    ts_col = ts_cols[0]
    
    # Normalize each row
    events = []
    parse_failures = 0
    
    for row in rows:
        # Parse timestamp
        ts_value = row.get(ts_col)
        epoch, ts_text = parse_timestamp(ts_value, timezone)
        
        if epoch is None:
            parse_failures += 1
            continue
        
        # Extract mapped fields
        event_type = _get_mapped(row, col_map, "event_type", "UNKNOWN")
        event_label = _get_mapped(row, col_map, "event_label", "")
        generation = _get_mapped(row, col_map, "generation", "")
        rat = _get_mapped(row, col_map, "rat", "")
        
        # Infer generation/rat from event text if not explicitly set
        if not generation or generation.upper() == "UNKNOWN":
            generation, rat = _infer_generation(event_type, event_label, row, col_map)
        elif generation.upper() in GENERATION_HINTS:
            gen_tuple = GENERATION_HINTS[generation.upper()]
            generation = gen_tuple[0]
            if not rat or rat.upper() == "UNKNOWN":
                rat = gen_tuple[1]
        
        # Classify event type
        event_type = _classify_event_type(event_type, event_label)
        
        # Build raw dict from all columns not explicitly mapped
        raw = {}
        for col, val in row.items():
            if col not in col_map and val is not None and str(val).strip():
                raw[col.lower()] = val
        
        # Create normalized event
        event = make_radio_event(
            time_epoch=epoch,
            time_text=ts_text,
            timezone=timezone or "Asia/Qatar",
            event_type=event_type,
            event_label=event_label or str(row.get(ts_col, "")),
            generation=generation or "UNKNOWN",
            rat=rat or "UNKNOWN",
            cell_id=_get_mapped(row, col_map, "cell_id"),
            tac=_get_mapped(row, col_map, "tac"),
            pci=_get_mapped(row, col_map, "pci"),
            earfcn=_get_mapped(row, col_map, "earfcn"),
            nrarfcn=_get_mapped(row, col_map, "nrarfcn"),
            imsi=_get_mapped(row, col_map, "imsi"),
            guti=_get_mapped(row, col_map, "guti"),
            tmsi=_get_mapped(row, col_map, "tmsi"),
            ue_ip=_get_mapped(row, col_map, "ue_ip"),
            rsrp=_safe_float(_get_mapped(row, col_map, "rsrp")),
            rsrq=_safe_float(_get_mapped(row, col_map, "rsrq")),
            sinr=_safe_float(_get_mapped(row, col_map, "sinr")),
            cqi=_safe_float(_get_mapped(row, col_map, "cqi")),
            ta=_safe_float(_get_mapped(row, col_map, "ta")),
            dl_bler=_safe_float(_get_mapped(row, col_map, "dl_bler")),
            ul_bler=_safe_float(_get_mapped(row, col_map, "ul_bler")),
            throughput_dl_kbps=_safe_float(_get_mapped(row, col_map, "throughput_dl_kbps")),
            throughput_ul_kbps=_safe_float(_get_mapped(row, col_map, "throughput_ul_kbps")),
            handover=_extract_handover(event_type, row, col_map),
            paging=_extract_paging(event_type, row, col_map),
            raw=raw,
        )
        events.append(event)
    
    if parse_failures > 0:
        logger.warning(f"Failed to parse {parse_failures}/{len(rows)} timestamps")
    
    # Sort by time
    events.sort(key=lambda e: e["time_epoch"])
    
    logger.info(f"Normalized {len(events)} events from {len(rows)} rows")
    return events, {k: v for k, v in col_map.items()}, unmapped


def _get_mapped(row: Dict, col_map: Dict[str, str], target_field: str, default=None):
    """Get value from row using column mapping."""
    for raw_col, mapped_field in col_map.items():
        if mapped_field == target_field:
            val = row.get(raw_col)
            if val is not None and str(val).strip():
                return str(val).strip()
    return default


def _safe_float(value) -> Optional[float]:
    """Safely convert to float, return None on failure."""
    if value is None:
        return None
    try:
        # Handle strings like "-95.5 dBm" 
        val_str = str(value).strip()
        # Extract numeric part
        match = re.search(r'[-+]?\d*\.?\d+', val_str)
        if match:
            return float(match.group())
        return None
    except (ValueError, TypeError):
        return None


def _infer_generation(event_type: str, event_label: str, row: Dict, col_map: Dict) -> Tuple[str, str]:
    """Infer generation and RAT from event text and known field presence."""
    text = f"{event_type} {event_label}".upper()
    
    # Check all row values for generation hints
    for val in row.values():
        val_upper = str(val).upper().strip()
        if val_upper in GENERATION_HINTS:
            gen, rat = GENERATION_HINTS[val_upper]
            return gen, rat
    
    # Check text content
    for keyword, (gen, rat) in GENERATION_HINTS.items():
        if keyword.upper() in text:
            return gen, rat
    
    # Heuristic: if EARFCN is present → 4G; if NRARFCN → 5G
    earfcn = _get_mapped(row, col_map, "earfcn")
    nrarfcn = _get_mapped(row, col_map, "nrarfcn")
    if nrarfcn:
        return "5G", "NR"
    if earfcn:
        return "4G", "EUTRAN"
    
    return "UNKNOWN", "UNKNOWN"


def _classify_event_type(event_type: str, event_label: str) -> str:
    """Map raw event type text to a known event type enum."""
    text = f"{event_type} {event_label}".upper()
    
    # Map to known types
    mappings = [
        (["RADIO LINK FAILURE", "RLF", "RADIO_LINK_FAILURE"], "RLF"),
        (["HANDOVER FAILURE", "HO FAIL", "HO_FAIL", "HANDOVER_FAILURE"], "HO_FAIL"),
        (["HANDOVER SUCCESS", "HO SUCCESS", "HO_SUCCESS", "HANDOVER_SUCCESS"], "HO_SUCCESS"),
        (["HANDOVER ATTEMPT", "HO ATTEMPT", "HO_ATTEMPT", "HANDOVER PREPARATION"], "HO_ATTEMPT"),
        (["CSFB", "CS FALLBACK", "CS_FALLBACK"], "CSFB"),
        (["SRVCC"], "SRVCC"),
        (["PAGING"], "PAGING"),
        (["RRC SETUP", "RRC_SETUP", "RRC CONNECTION SETUP"], "RRC_SETUP"),
        (["RRC RELEASE", "RRC_RELEASE", "RRC CONNECTION RELEASE"], "RRC_RELEASE"),
        (["RRC RE-ESTABLISHMENT", "RRC REESTABLISHMENT", "RRC_REESTABLISHMENT"], "RRC_REESTABLISHMENT"),
        (["ATTACH"], "ATTACH"),
        (["DETACH"], "DETACH"),
        (["TRACKING AREA UPDATE", "TAU"], "TAU"),
        (["SERVICE REQUEST", "SERVICE_REQUEST"], "SERVICE_REQUEST"),
        (["MEASUREMENT REPORT", "MEASUREMENT_REPORT"], "MEASUREMENT_REPORT"),
    ]
    
    for keywords, mapped_type in mappings:
        for kw in keywords:
            if kw in text:
                return mapped_type
    
    # Return original if no match
    return event_type if event_type else "UNKNOWN"


def _extract_handover(event_type: str, row: Dict, col_map: Dict) -> Optional[Dict]:
    """Extract handover info if this is a handover event."""
    if not event_type or "HO" not in event_type.upper():
        return None
    return {
        "attempt": "ATTEMPT" in event_type.upper() or "HO" in event_type.upper(),
        "success": "SUCCESS" in event_type.upper(),
        "from_cell": _get_mapped(row, col_map, "cell_id") or "",
        "to_cell": "",  # Would need target cell column
    }


def _extract_paging(event_type: str, row: Dict, col_map: Dict) -> Optional[Dict]:
    """Extract paging info if this is a paging event."""
    if not event_type or "PAGING" not in event_type.upper():
        return None
    return {
        "attempt": True,
        "success": "SUCCESS" in str(row).upper(),
    }
