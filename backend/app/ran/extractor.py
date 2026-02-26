"""
RAN Event Extractor

Runs TShark with RAN-specific field packs and normalizes output
to a common event schema.
"""
import subprocess
import csv
import io
import logging
from typing import List, Dict, Any, Tuple

from .field_packs import RAN_FIELD_PACKS, get_protocol_fields
from .taxonomy import Generation, Protocol, get_procedure_label

logger = logging.getLogger(__name__)


def extract_ran_events(pcap_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, bool]]:
    """
    Extract RAN events from PCAP using TShark.
    
    Args:
        pcap_path: Path to PCAP file
        
    Returns:
        Tuple of (events_list, coverage_flags_dict)
    """
    all_events = []
    coverage_flags = {
        "has_2g": False,
        "has_3g": False,
        "has_4g": False,
        "has_5g": False,
        "has_s1ap": False,
        "has_ngap": False,
        "has_ranap": False,
        "has_bssap": False,
        "has_x2ap": False,
        "has_xnap": False,
        "has_sctp": False,
        "has_sccp": False,
    }
    
    # Extract each protocol pack
    for protocol, (display_filter, fields) in RAN_FIELD_PACKS.items():
        try:
            events = _run_tshark_extraction(pcap_path, display_filter, fields)
            if events:
                # Set coverage flags
                flag_key = f"has_{protocol.lower()}"
                if flag_key in coverage_flags:
                    coverage_flags[flag_key] = True
                
                # Set generation flags
                if protocol in ["S1AP", "X2AP"]:
                    coverage_flags["has_4g"] = True
                elif protocol in ["NGAP", "XnAP"]:
                    coverage_flags["has_5g"] = True
                elif protocol == "RANAP":
                    coverage_flags["has_3g"] = True
                elif protocol == "BSSAP":
                    coverage_flags["has_2g"] = True
                elif protocol == "SCTP":
                    coverage_flags["has_sctp"] = True
                elif protocol == "SCCP":
                    coverage_flags["has_sccp"] = True
                
                # Normalize events to common schema
                normalized = _normalize_events(events, protocol)
                all_events.extend(normalized)
                logger.info(f"Extracted {len(events)} {protocol} events")
        except Exception as e:
            logger.warning(f"Failed to extract {protocol}: {e}")
    
    # Sort by timestamp
    all_events.sort(key=lambda x: x.get("time_epoch", 0))
    
    logger.info(f"Total RAN events extracted: {len(all_events)}")
    return all_events, coverage_flags


def _run_tshark_extraction(
    pcap_path: str, 
    display_filter: str, 
    fields: List[str]
) -> List[Dict[str, Any]]:
    """
    Run TShark with specific filter and fields.
    
    Returns list of row dictionaries.
    """
    cmd = [
        "tshark", "-n", "-r", pcap_path,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]
    
    for field in fields:
        cmd.extend(["-e", field])
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=True
        )
        
        if not result.stdout.strip():
            return []
        
        # Parse CSV output
        data = []
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            # Filter out empty rows
            cleaned = {k: v for k, v in row.items() if v}
            if cleaned:
                data.append(cleaned)
        
        return data
        
    except subprocess.TimeoutExpired:
        logger.error(f"TShark timeout for filter: {display_filter}")
        return []
    except subprocess.CalledProcessError as e:
        # Don't log error for "no packets match" (exit code 0 with empty output)
        if e.returncode != 0:
            logger.debug(f"TShark returned no data for {display_filter}")
        return []
    except Exception as e:
        logger.error(f"TShark extraction error: {e}")
        return []


def _normalize_events(
    events: List[Dict[str, Any]], 
    protocol: str
) -> List[Dict[str, Any]]:
    """
    Normalize raw TShark output to common event schema.
    """
    normalized = []
    
    for event in events:
        # Determine generation
        generation = _get_generation(protocol)
        
        # Extract procedure code and label
        proc_code = _extract_procedure_code(event, protocol)
        proc_label = None
        if proc_code is not None:
            proc_label = get_procedure_label(protocol, proc_code)
        
        # Extract cause information
        cause_raw, cause_label = _extract_cause(event, protocol)
        
        # Build UE identifiers
        ue_ids = _extract_ue_ids(event, protocol)
        
        # Build normalized event
        normalized_event = {
            "time_epoch": float(event.get("frame.time_epoch", 0) or 0),
            "frame": int(event.get("frame.number", 0) or 0),
            "generation": generation.value,
            "protocol": protocol,
            "procedure_code": proc_code,
            "procedure_label": proc_label,
            "cause_raw": cause_raw,
            "cause_label": cause_label,
            "ue_ids": ue_ids,
            "addr": {
                "src": event.get("ip.src", ""),
                "dst": event.get("ip.dst", ""),
            },
            "transport": {
                "sctp_assoc_id": event.get("sctp.verification_tag"),
                "sctp_stream": event.get("sctp.data_sid"),
                "sccp_calling": event.get("sccp.calling.ssn"),
                "sccp_called": event.get("sccp.called.ssn"),
            }
        }
        
        normalized.append(normalized_event)
    
    return normalized


def _get_generation(protocol: str) -> Generation:
    """Determine generation from protocol"""
    if protocol in ["S1AP", "X2AP"]:
        return Generation.G4
    elif protocol in ["NGAP", "XnAP"]:
        return Generation.G5
    elif protocol == "RANAP":
        return Generation.G3
    elif protocol == "BSSAP":
        return Generation.G2
    return Generation.UNKNOWN


def _extract_procedure_code(event: Dict[str, Any], protocol: str) -> int:
    """Extract procedure code from event"""
    field_map = {
        "S1AP": "s1ap.procedureCode",
        "NGAP": "ngap.procedureCode",
        "X2AP": "x2ap.procedureCode",
        "XnAP": "xnap.procedureCode",
        "RANAP": "ranap.procedureCode",
    }
    
    field = field_map.get(protocol)
    if field and field in event:
        try:
            return int(event[field])
        except (ValueError, TypeError):
            pass
    
    return None


def _extract_cause(event: Dict[str, Any], protocol: str) -> Tuple[str, str]:
    """
    Extract cause code and label from event.
    Returns (cause_raw, cause_label)
    """
    cause_raw = None
    cause_label = None
    
    # Try protocol-specific cause fields
    cause_fields = {
        "S1AP": ["s1ap.Cause", "s1ap.cause.radioNetwork", "s1ap.cause.transport", 
                 "s1ap.cause.nas", "s1ap.cause.protocol", "s1ap.cause.misc"],
        "NGAP": ["ngap.Cause", "ngap.cause.radioNetwork", "ngap.cause.transport",
                 "ngap.cause.nas", "ngap.cause.protocol", "ngap.cause.misc"],
        "X2AP": ["x2ap.Cause"],
        "XnAP": ["xnap.Cause"],
        "RANAP": ["ranap.Cause"],
        "BSSAP": ["bssap.cause"],
    }
    
    fields = cause_fields.get(protocol, [])
    for field in fields:
        if field in event and event[field]:
            cause_raw = event[field]
            # For now, use raw value as label; could enhance with mappings
            cause_label = cause_raw
            break
    
    return cause_raw, cause_label


def _extract_ue_ids(event: Dict[str, Any], protocol: str) -> Dict[str, str]:
    """Extract UE identifiers from event"""
    ue_ids = {
        "mme_ue_s1ap_id": None,
        "enb_ue_s1ap_id": None,
        "amf_ue_ngap_id": None,
        "ran_ue_ngap_id": None,
        "imsi": None,
        "tmsi": None,
    }
    
    # 4G S1AP IDs
    if "s1ap.MME_UE_S1AP_ID" in event:
        ue_ids["mme_ue_s1ap_id"] = event["s1ap.MME_UE_S1AP_ID"]
    if "s1ap.ENB_UE_S1AP_ID" in event:
        ue_ids["enb_ue_s1ap_id"] = event["s1ap.ENB_UE_S1AP_ID"]
    
    # 5G NGAP IDs
    if "ngap.AMF_UE_NGAP_ID" in event:
        ue_ids["amf_ue_ngap_id"] = event["ngap.AMF_UE_NGAP_ID"]
    if "ngap.RAN_UE_NGAP_ID" in event:
        ue_ids["ran_ue_ngap_id"] = event["ngap.RAN_UE_NGAP_ID"]
    
    # 3G RANAP - would need additional fields
    # 2G BSSAP - typically uses SCCP for correlation
    
    return ue_ids
