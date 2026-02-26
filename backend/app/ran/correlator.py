"""
RAN Event Correlator

Groups RAN events into UE timelines using available identifiers.
"""
import logging
from collections import defaultdict
from typing import List, Dict, Any

from .taxonomy import Generation

logger = logging.getLogger(__name__)


def build_ue_timelines(
    events: List[Dict[str, Any]], 
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Group events into UE-centric timelines.
    
    Correlation strategy by generation:
    - 5G: (AMF_UE_NGAP_ID, RAN_UE_NGAP_ID)
    - 4G: (MME_UE_S1AP_ID, ENB_UE_S1AP_ID)
    - 3G/2G: SCCP pair or transport tuple fallback
    
    Args:
        events: List of normalized RAN events
        coverage_flags: Protocol coverage flags
        
    Returns:
        List of timeline dictionaries
    """
    timelines_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "ue_key": None,
        "generation": None,
        "events": [],
        "time_start": float("inf"),
        "time_end": 0,
        "protocols": set(),
    })
    
    for event in events:
        ue_key = _derive_ue_key(event)
        
        if not ue_key:
            continue
        
        timeline = timelines_map[ue_key]
        timeline["ue_key"] = ue_key
        timeline["generation"] = event.get("generation", "Unknown")
        timeline["events"].append(event)
        timeline["protocols"].add(event.get("protocol", "Unknown"))
        
        # Update time bounds
        time_epoch = event.get("time_epoch", 0)
        if time_epoch < timeline["time_start"]:
            timeline["time_start"] = time_epoch
        if time_epoch > timeline["time_end"]:
            timeline["time_end"] = time_epoch
    
    # Convert to list and clean up
    timelines = []
    for key, timeline in timelines_map.items():
        if timeline["events"]:
            # Sort events by time
            timeline["events"].sort(key=lambda x: x.get("time_epoch", 0))
            
            # Convert sets to lists for JSON serialization
            timeline["protocols"] = list(timeline["protocols"])
            
            # Fix infinite time_start
            if timeline["time_start"] == float("inf"):
                timeline["time_start"] = 0
            
            # Add event count
            timeline["event_count"] = len(timeline["events"])
            
            # Calculate duration
            timeline["duration"] = timeline["time_end"] - timeline["time_start"]
            
            timelines.append(timeline)
    
    # Sort timelines by start time
    timelines.sort(key=lambda x: x.get("time_start", 0))
    
    logger.info(f"Built {len(timelines)} UE timelines from {len(events)} events")
    return timelines


def _derive_ue_key(event: Dict[str, Any]) -> str:
    """
    Derive a unique UE key from event identifiers.
    
    Priority:
    1. 5G: AMF_UE_NGAP_ID + RAN_UE_NGAP_ID
    2. 4G: MME_UE_S1AP_ID + ENB_UE_S1AP_ID
    3. 3G/2G: SCCP calling/called pair
    4. Fallback: Transport tuple (IP pair + SCTP assoc)
    """
    ue_ids = event.get("ue_ids", {})
    transport = event.get("transport", {})
    addr = event.get("addr", {})
    generation = event.get("generation", "")
    
    # 5G: NGAP IDs
    amf_id = ue_ids.get("amf_ue_ngap_id")
    ran_id = ue_ids.get("ran_ue_ngap_id")
    if amf_id and ran_id:
        return f"5g:amf={amf_id}:ran={ran_id}"
    
    # 4G: S1AP IDs
    mme_id = ue_ids.get("mme_ue_s1ap_id")
    enb_id = ue_ids.get("enb_ue_s1ap_id")
    if mme_id and enb_id:
        return f"4g:mme={mme_id}:enb={enb_id}"
    
    # Partial 5G (only one ID available)
    if amf_id:
        return f"5g:amf={amf_id}"
    if ran_id:
        return f"5g:ran={ran_id}"
    
    # Partial 4G (only one ID available)
    if mme_id:
        return f"4g:mme={mme_id}"
    if enb_id:
        return f"4g:enb={enb_id}"
    
    # 3G/2G: SCCP pair
    sccp_calling = transport.get("sccp_calling")
    sccp_called = transport.get("sccp_called")
    if sccp_calling and sccp_called:
        return f"sccp:{sccp_calling}-{sccp_called}"
    
    # Fallback: Transport tuple
    sctp_assoc = transport.get("sctp_assoc_id")
    src_ip = addr.get("src", "")
    dst_ip = addr.get("dst", "")
    
    if sctp_assoc and src_ip and dst_ip:
        # Sort IPs for bidirectional consistency
        ip_pair = tuple(sorted([src_ip, dst_ip]))
        return f"sctp:{sctp_assoc}:{ip_pair[0]}-{ip_pair[1]}"
    
    # Last resort: Just IP pair
    if src_ip and dst_ip:
        ip_pair = tuple(sorted([src_ip, dst_ip]))
        return f"ip:{ip_pair[0]}-{ip_pair[1]}"
    
    return None
