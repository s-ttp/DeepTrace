"""
Cross-plane event timeline builder.

Merges PCAP and Groundhog events into a unified, time-sorted timeline.
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def build_cross_plane_timeline(
    pcap_events: List[Dict[str, Any]],
    groundhog_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Build a merged timeline from PCAP and Groundhog events.
    
    Each entry is tagged with its source and normalized to a common format.
    
    Returns:
        List of timeline entries sorted by time_epoch
    """
    timeline = []
    
    # Add PCAP events
    for ev in pcap_events:
        time_epoch = None
        for key in ["time_epoch", "timestamp", "start_time", "time_start"]:
            if ev.get(key) is not None:
                try:
                    time_epoch = float(ev[key])
                    break
                except (ValueError, TypeError):
                    continue
        
        if time_epoch is None:
            continue
        
        timeline.append({
            "time_epoch": time_epoch,
            "source": "PCAP",
            "event_type": ev.get("protocol") or ev.get("type") or ev.get("procedure_label", "unknown"),
            "description": _pcap_description(ev),
            "severity": ev.get("severity", "info"),
            "details": {
                "src_ip": ev.get("src_ip") or ev.get("addr", {}).get("src", ""),
                "dst_ip": ev.get("dst_ip") or ev.get("addr", {}).get("dst", ""),
                "protocol": ev.get("protocol", ""),
            }
        })
    
    # Add Groundhog events
    for ev in groundhog_events:
        time_epoch = ev.get("time_epoch")
        if time_epoch is None:
            continue
        
        timeline.append({
            "time_epoch": time_epoch,
            "source": "GROUNDHOG",
            "event_type": ev.get("event_type", "UNKNOWN"),
            "description": ev.get("event_label") or ev.get("event_type", ""),
            "severity": _groundhog_severity(ev),
            "details": {
                "generation": ev.get("generation", ""),
                "cell_id": ev.get("cell_id", ""),
                "rsrp": ev.get("rsrp"),
                "sinr": ev.get("sinr"),
            }
        })
    
    # Sort by time
    timeline.sort(key=lambda x: x["time_epoch"])
    
    logger.info(f"Built cross-plane timeline: {len(timeline)} events "
                f"({sum(1 for e in timeline if e['source'] == 'PCAP')} PCAP, "
                f"{sum(1 for e in timeline if e['source'] == 'GROUNDHOG')} Groundhog)")
    
    return timeline


def _pcap_description(ev: Dict) -> str:
    """Generate a brief description for a PCAP event."""
    protocol = ev.get("protocol", "")
    procedure = ev.get("procedure_label", "")
    cause = ev.get("cause_label", "")
    
    parts = [p for p in [protocol, procedure, cause] if p]
    return " - ".join(parts) if parts else "PCAP event"


def _groundhog_severity(ev: Dict) -> str:
    """Determine severity of a Groundhog event."""
    event_type = ev.get("event_type", "").upper()
    
    if event_type in ["RLF", "HO_FAIL", "PAGING"]:
        return "critical"
    elif event_type in ["HO_ATTEMPT", "RRC_REESTABLISHMENT", "CSFB", "SRVCC"]:
        return "warning"
    return "info"
