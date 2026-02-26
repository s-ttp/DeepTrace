"""
Robust timestamp parsing and timezone handling for Groundhog traces.

Supports: epoch floats, ISO 8601, common datetime formats.
Default timezone: Asia/Qatar (UTC+3) if not specified.
"""
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Common datetime formats to try
DATETIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%d/%m/%Y %H:%M:%S.%f",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S.%f",
    "%Y%m%d%H%M%S",
    "%Y%m%d %H%M%S",
]

# Named timezone offsets
TIMEZONE_OFFSETS = {
    "Asia/Qatar": timedelta(hours=3),
    "UTC": timedelta(hours=0),
    "GMT": timedelta(hours=0),
    "AST": timedelta(hours=3),      # Arabia Standard Time
    "GST": timedelta(hours=4),      # Gulf Standard Time
    "IST": timedelta(hours=5, minutes=30),
    "CET": timedelta(hours=1),
    "EET": timedelta(hours=2),
    "EST": timedelta(hours=-5),
    "PST": timedelta(hours=-8),
    "CST": timedelta(hours=-6),
}

DEFAULT_TIMEZONE = "Asia/Qatar"


def parse_timestamp(value, tz_name: str = None) -> Tuple[Optional[float], str]:
    """
    Parse a timestamp value into (epoch_float, original_string).
    
    Args:
        value: The timestamp value (str, float, int)
        tz_name: Timezone name override (default: Asia/Qatar)
        
    Returns:
        Tuple of (epoch_float or None, original_string)
    """
    if value is None:
        return None, ""

    original = str(value).strip()
    if not original:
        return None, ""

    tz_name = tz_name or DEFAULT_TIMEZONE
    tz_offset = TIMEZONE_OFFSETS.get(tz_name, timedelta(hours=3))
    tz_info = timezone(tz_offset)

    # Try 1: Numeric epoch
    try:
        epoch = float(value)
        # Sanity check: epoch should be > 2000-01-01 and < 2100-01-01
        if 946684800 < epoch < 4102444800:
            return epoch, original
        # Could be millisecond epoch
        if 946684800000 < epoch < 4102444800000:
            return epoch / 1000.0, original
    except (ValueError, TypeError):
        pass

    # Try 2: ISO 8601 with timezone info
    text = original
    # Check for timezone suffix like +03:00 or Z
    tz_match = re.search(r'([+-]\d{2}:\d{2}|Z)$', text)
    if tz_match:
        try:
            dt = datetime.fromisoformat(text.replace('Z', '+00:00'))
            return dt.timestamp(), original
        except (ValueError, AttributeError):
            pass

    # Try 3: Common datetime formats (assume provided timezone)
    for fmt in DATETIME_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            # Apply timezone since format has no tz info
            dt = dt.replace(tzinfo=tz_info)
            return dt.timestamp(), original
        except ValueError:
            continue

    # Try 4: Regex-based extraction for embedded timestamps
    # Pattern: something like "2024-01-15 10:30:45" embedded in text
    ts_match = re.search(r'(\d{4}[-/]\d{1,2}[-/]\d{1,2}[\sT]\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)', text)
    if ts_match:
        extracted = ts_match.group(1).replace('/', '-').replace('T', ' ')
        for fmt in ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]:
            try:
                dt = datetime.strptime(extracted, fmt)
                dt = dt.replace(tzinfo=tz_info)
                return dt.timestamp(), original
            except ValueError:
                continue

    logger.warning(f"Could not parse timestamp: '{original}'")
    return None, original


def detect_timezone_from_data(values: list) -> Optional[str]:
    """
    Try to detect timezone from a list of timestamp strings.
    
    Checks for timezone indicators like +03:00, AST, UTC etc.
    Returns timezone name or None.
    """
    for v in values[:20]:  # Sample first 20 values
        text = str(v).strip()
        # Check for +HH:MM offset
        match = re.search(r'([+-])(\d{2}):(\d{2})$', text)
        if match:
            sign = 1 if match.group(1) == '+' else -1
            hours = int(match.group(2))
            offset = sign * hours
            # Map common offsets
            if offset == 3:
                return "Asia/Qatar"
            elif offset == 0:
                return "UTC"
            else:
                return f"UTC{'+' if offset >= 0 else ''}{offset}"

        # Check for named timezone
        for tz_name in TIMEZONE_OFFSETS:
            if tz_name in text:
                return tz_name

    return None
