import shutil
import subprocess
import logging
import json
import csv
import io
from typing import List, Dict, Any
from .tshark_field_packs import get_all_fields

logger = logging.getLogger(__name__)

def tshark_available() -> bool:
    """Check if tshark is available in the system path"""
    return shutil.which("tshark") is not None

# Global cache for supported fields
_SUPPORTED_FIELDS_CACHE = None

def validate_field_capabilities() -> List[str]:
    """
    Run tshark -G fields to check which requests fields are actually supported 
    by the installed version. Prevents errors on older TShark versions.
    """
    global _SUPPORTED_FIELDS_CACHE
    if _SUPPORTED_FIELDS_CACHE is not None:
        return _SUPPORTED_FIELDS_CACHE

    if not tshark_available():
        return []

    requested_fields = get_all_fields()
    supported = []
    
    # We can't easily check all at once efficiently against -G output (huge).
    # Instead, we run a dummy extraction on an empty/small pcap or just trust 
    # that we filtered the lists based on the version check in verification.
    # BETTER APPROACH: Run `tshark -G fields` and grep for our specific fields.
    # OR: Just try to run with all fields, if it fails, fallback? No, TShark errors out.
    
    # Strategy: Dump all valid fields to a set once.
    try:
        # This command lists ALL fields. It can be slow (seconds).
        # We process line by line.
        cmd = ["tshark", "-G", "fields"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        
        valid_fields_set = set()
        for line in process.stdout:
            # Format: F  Human Name  filter.name ...
            parts = line.split('\t')
            if len(parts) >= 3:
                valid_fields_set.add(parts[2])
        
        process.wait()
        
        # Filter requested fields
        missing = []
        for rf in requested_fields:
            if rf in valid_fields_set:
                supported.append(rf)
            else:
                missing.append(rf)
        
        if missing:
            logger.warning(f"The following TShark fields are not supported by installed version and will be skipped: {missing}")
            
        _SUPPORTED_FIELDS_CACHE = supported
        return supported

    except Exception as e:
        logger.error(f"Failed to validate TShark fields: {e}")
        # Fallback: return all and hope for best (behavior before this change)
        return requested_fields

# ============================================================================
# Mode A: Stats/Analytics (-z)
# ============================================================================

def get_tshark_stats(pcap_path: str) -> Dict[str, Any]:
    """
    Run TShark stats commands to get high-level analytics.
    Returns a dictionary with keys: 'io_stats', 'conversations', 'endpoints', 'expert_info'
    """
    if not tshark_available():
        return {}

    stats = {}
    
    # 1. Expert Info
    try:
        # -G used for glossary/reports, but -z expert is standard for stats
        # actually -z expert -q is best for summary
        cmd = ["tshark", "-r", pcap_path, "-q", "-z", "expert", "-o", "tcp.desegment_tcp_streams:TRUE"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        stats["expert_info"] = _parse_expert_info(result.stdout)
    except Exception as e:
        logger.warning(f"TShark Expert Info failed: {e}")
        stats["expert_info"] = []

    # 2. IO Stats (1 second intervals)
    try:
        cmd = ["tshark", "-r", pcap_path, "-q", "-z", "io,stat,1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        stats["io_stats"] = _parse_io_stats(result.stdout)
    except Exception as e:
        logger.warning(f"TShark IO Stats failed: {e}")
        stats["io_stats"] = []

    # 3. SCTP Association Stats (New feature)
    try:
        cmd = ["tshark", "-r", pcap_path, "-q", "-z", "sctp,stat"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        # We store the raw text output for the LLM to interpret or basic display
        stats["sctp_stats"] = result.stdout
    except Exception as e:
        logger.warning(f"TShark SCTP Stats failed: {e}")

    return stats

def _parse_expert_info(output: str) -> List[Dict[str, str]]:
    """Parse TShark expert info text output"""
    findings = []
    lines = output.splitlines()
    for line in lines:
        if any(level in line for level in ["Error", "Warn", "Note"]):
            # Very basic parsing - in real app would use regex
            parts = line.split()
            if len(parts) > 3:
                findings.append({
                    "severity": parts[0],
                    "group": parts[1],
                    "protocol": parts[2],
                    "summary": " ".join(parts[3:])
                })
    return findings

def _parse_io_stats(output: str) -> List[Dict[str, Any]]:
    """Parse TShark IO stats table"""
    # Simply return raw lines for POC, or better yet, basic structured data
    # Real implementation would parse the ASCII table
    return [{"raw": line} for line in output.splitlines() if "|" in line]


# ============================================================================
# Mode B: Targeted Fields (-T fields) - DEFAULT DEEP DECODE
# ============================================================================

def extract_telecom_fields(pcap_path: str, display_filter: str = None) -> List[Dict[str, Any]]:
    """
    Extract specific telecom fields using tshark -T fields.
    Efficient and targeted.
    """
    if not tshark_available():
        return []
    
    # Feature 8: Dynamic capability check
    fields = validate_field_capabilities()
    
    cmd = [
        "tshark", "-n", "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f", # First occurrence only to keep CSV clean
        "-o", "tcp.desegment_tcp_streams:TRUE" # Reassemble
    ]
    
    for field in fields:
        cmd.extend(["-e", field])
        
    if display_filter:
        cmd.extend(["-Y", display_filter])
        
    try:
        # 60s timeout for deep decode
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
        
        # Parse CSV output
        data = []
        # Use csv module to handle quoted fields properly
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            # Clean up keys/values if needed
            cleaned_row = {k: v for k, v in row.items() if v} # Remove empty fields
            if cleaned_row:
                data.append(cleaned_row)
                
        return data
        
    except subprocess.CalledProcessError as e:
        logger.error(f"TShark fields extraction failed: {e.stderr}")
        return []
    except Exception as e:
        logger.error(f"Error running TShark fields: {e}")
        return []


# ============================================================================
# Mode C: JSON Decode (-T json) - SURGICAL ONLY
# ============================================================================

def run_tshark_json(pcap_path: str, display_filter: str = None, packet_count: int = 20) -> List[Dict[str, Any]]:
    """
    Run tshark -T json for surgical inspection.
    Restricted to small packet counts by default.
    """
    if not tshark_available():
        return []

    cmd = ["tshark", "-n", "-r", pcap_path, "-T", "json"]
    
    if display_filter:
        cmd.extend(["-Y", display_filter])
        
    # Always cap packet count for safety unless explicitly huge
    cmd.extend(["-c", str(packet_count)])

    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True,
            timeout=15
        )
        return json.loads(result.stdout)
    except Exception as e:
        logger.error(f"TShark JSON decode failed: {e}")
        return []
