"""
Groundhog summary generator.

Produces groundhog_summary.json with statistics from normalized events.
"""
import json
import logging
from typing import List, Dict, Any
from collections import Counter

logger = logging.getLogger(__name__)


def generate_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary from normalized Groundhog radio events.
    
    Returns dict with:
    - total_events
    - time_range (min/max epoch + formatted)
    - event_type_counts
    - generation_counts
    - identifiers_found
    - kpi_statistics (if available)
    """
    if not events:
        return {"total_events": 0, "message": "No events found"}
    
    # Counts
    event_types = Counter()
    generations = Counter()
    rats = Counter()
    
    # Identifiers
    imsis = set()
    gutis = set()
    cell_ids = set()
    ue_ips = set()
    
    # Time range
    epochs = []
    
    # KPIs
    rsrp_values = []
    rsrq_values = []
    sinr_values = []
    dl_tp_values = []
    ul_tp_values = []
    
    for event in events:
        event_types[event.get("event_type", "UNKNOWN")] += 1
        generations[event.get("generation", "UNKNOWN")] += 1
        rats[event.get("rat", "UNKNOWN")] += 1
        
        epoch = event.get("time_epoch")
        if epoch:
            epochs.append(epoch)
        
        if event.get("imsi"):
            imsis.add(event["imsi"])
        if event.get("guti"):
            gutis.add(event["guti"])
        if event.get("cell_id"):
            cell_ids.add(event["cell_id"])
        if event.get("ue_ip"):
            ue_ips.add(event["ue_ip"])
        
        if event.get("rsrp") is not None:
            rsrp_values.append(event["rsrp"])
        if event.get("rsrq") is not None:
            rsrq_values.append(event["rsrq"])
        if event.get("sinr") is not None:
            sinr_values.append(event["sinr"])
        if event.get("throughput_dl_kbps") is not None:
            dl_tp_values.append(event["throughput_dl_kbps"])
        if event.get("throughput_ul_kbps") is not None:
            ul_tp_values.append(event["throughput_ul_kbps"])
    
    # Build summary
    summary = {
        "total_events": len(events),
        "time_range": {
            "start_epoch": min(epochs) if epochs else None,
            "end_epoch": max(epochs) if epochs else None,
            "duration_seconds": (max(epochs) - min(epochs)) if len(epochs) >= 2 else 0,
        },
        "event_type_counts": dict(event_types.most_common()),
        "generation_counts": dict(generations.most_common()),
        "rat_counts": dict(rats.most_common()),
        "identifiers_found": {
            "imsi_count": len(imsis),
            "imsi_list": sorted(imsis)[:10],
            "guti_count": len(gutis),
            "cell_id_count": len(cell_ids),
            "cell_id_list": sorted(cell_ids)[:20],
            "ue_ip_count": len(ue_ips),
            "ue_ip_list": sorted(ue_ips)[:10],
        },
    }
    
    # KPI statistics
    kpis = {}
    if rsrp_values:
        kpis["rsrp"] = _stat_summary(rsrp_values, "dBm")
    if rsrq_values:
        kpis["rsrq"] = _stat_summary(rsrq_values, "dB")
    if sinr_values:
        kpis["sinr"] = _stat_summary(sinr_values, "dB")
    if dl_tp_values:
        kpis["throughput_dl_kbps"] = _stat_summary(dl_tp_values, "kbps")
    if ul_tp_values:
        kpis["throughput_ul_kbps"] = _stat_summary(ul_tp_values, "kbps")
    
    if kpis:
        summary["kpi_statistics"] = kpis
    
    # Radio issue highlights
    radio_issues = {}
    for et in ["RLF", "HO_FAIL", "PAGING", "RRC_REESTABLISHMENT", "CSFB", "SRVCC"]:
        if event_types.get(et, 0) > 0:
            radio_issues[et] = event_types[et]
    if radio_issues:
        summary["radio_issues_detected"] = radio_issues
    
    logger.info(f"Generated summary: {len(events)} events, {len(epochs)} with timestamps")
    return summary


def _stat_summary(values: list, unit: str) -> Dict[str, Any]:
    """Generate min/max/avg/count for a list of numeric values."""
    return {
        "count": len(values),
        "min": round(min(values), 2),
        "max": round(max(values), 2),
        "avg": round(sum(values) / len(values), 2),
        "unit": unit,
    }


def save_summary(summary: Dict[str, Any], output_path: str):
    """Save summary to JSON file."""
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    logger.info(f"Saved Groundhog summary to {output_path}")
