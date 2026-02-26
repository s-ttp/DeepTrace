"""
Correlation Scoring Engine.

Matches entities across PCAP and Groundhog data using identity keys
and time proximity with configurable confidence windows.
"""
import logging
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Time window thresholds (seconds)
WINDOW_STRONG = 5.0
WINDOW_MEDIUM = 10.0
WINDOW_WEAK = 20.0


def score_correlation(
    pcap_entity: Dict[str, Any],
    groundhog_entity: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Score the correlation between a PCAP entity and a Groundhog entity.
    
    Returns:
        Dict with match_type, confidence_pct, time_delta, matched_keys
    """
    matches = []
    confidence = 0
    
    # 1. IMSI exact match (highest confidence)
    pcap_imsi = _extract_id(pcap_entity, "imsi")
    gh_imsi = groundhog_entity.get("imsi")
    if pcap_imsi and gh_imsi and pcap_imsi == gh_imsi:
        matches.append(("IMSI", pcap_imsi))
        confidence = max(confidence, 95)
    
    # 2. GUTI/TMSI match
    pcap_guti = _extract_id(pcap_entity, "guti")
    gh_guti = groundhog_entity.get("guti")
    if pcap_guti and gh_guti and pcap_guti == gh_guti:
        matches.append(("GUTI", pcap_guti))
        confidence = max(confidence, 85)
    
    pcap_tmsi = _extract_id(pcap_entity, "tmsi")
    gh_tmsi = groundhog_entity.get("tmsi")
    if pcap_tmsi and gh_tmsi and pcap_tmsi == gh_tmsi:
        matches.append(("TMSI", pcap_tmsi))
        confidence = max(confidence, 85)
    
    # 3. UE IP match
    pcap_ip = _extract_id(pcap_entity, "ue_ip")
    gh_ip = groundhog_entity.get("ue_ip")
    if pcap_ip and gh_ip and pcap_ip == gh_ip:
        matches.append(("UE_IP", pcap_ip))
        confidence = max(confidence, 80)
    
    # 4. Cell ID + time window match
    pcap_cell = _extract_id(pcap_entity, "cell_id")
    gh_cell = groundhog_entity.get("cell_id")
    if pcap_cell and gh_cell and pcap_cell == gh_cell:
        matches.append(("CELL_ID", pcap_cell))
        confidence = max(confidence, 70)
    
    # 5. Time proximity scoring
    pcap_time = _extract_time(pcap_entity)
    gh_time = groundhog_entity.get("time_epoch")
    
    time_delta = None
    time_quality = "none"
    
    if pcap_time is not None and gh_time is not None:
        time_delta = abs(pcap_time - gh_time)
        
        if time_delta <= WINDOW_STRONG:
            time_quality = "strong"
            if not matches:
                confidence = max(confidence, 60)
            else:
                confidence = min(confidence + 10, 99)
        elif time_delta <= WINDOW_MEDIUM:
            time_quality = "medium"
            if not matches:
                confidence = max(confidence, 45)
            else:
                confidence = min(confidence + 5, 95)
        elif time_delta <= WINDOW_WEAK:
            time_quality = "weak"
            if not matches:
                confidence = max(confidence, 30)
    
    # No match at all
    if confidence == 0 and not matches:
        return None
    
    return {
        "match_type": matches[0][0] if matches else "TIME_PROXIMITY",
        "matched_keys": matches,
        "confidence_pct": confidence,
        "confidence_level": _level(confidence),
        "time_delta_seconds": round(time_delta, 3) if time_delta is not None else None,
        "time_quality": time_quality,
    }


def find_correlations(
    pcap_events: List[Dict[str, Any]],
    groundhog_events: List[Dict[str, Any]],
    min_confidence: int = 30,
) -> List[Dict[str, Any]]:
    """
    Find all correlations between PCAP and Groundhog events.
    
    Args:
        pcap_events: List of PCAP-derived events (flows, transactions, findings)
        groundhog_events: List of normalized Groundhog events
        min_confidence: Minimum confidence to include a match
        
    Returns:
        List of correlation results, sorted by confidence descending
    """
    correlations = []
    
    for i, pcap_ev in enumerate(pcap_events):
        for j, gh_ev in enumerate(groundhog_events):
            result = score_correlation(pcap_ev, gh_ev)
            if result and result["confidence_pct"] >= min_confidence:
                result["pcap_index"] = i
                result["groundhog_index"] = j
                result["pcap_event"] = _summarize_pcap(pcap_ev)
                result["groundhog_event"] = _summarize_gh(gh_ev)
                correlations.append(result)
    
    # Deduplicate: keep best match per groundhog event
    best_by_gh = {}
    for corr in correlations:
        gh_idx = corr["groundhog_index"]
        if gh_idx not in best_by_gh or corr["confidence_pct"] > best_by_gh[gh_idx]["confidence_pct"]:
            best_by_gh[gh_idx] = corr
    
    results = sorted(best_by_gh.values(), key=lambda x: x["confidence_pct"], reverse=True)
    logger.info(f"Found {len(results)} correlations (min confidence: {min_confidence}%)")
    return results


def _extract_id(entity: Dict, key: str) -> Optional[str]:
    """Extract an identifier from various possible locations in a PCAP entity."""
    # Direct key
    if entity.get(key):
        return str(entity[key])
    # Under identifiers
    ids = entity.get("identifiers", {})
    if ids.get(key):
        return str(ids[key])
    # Under ue_ids
    ue_ids = entity.get("ue_ids", {})
    if ue_ids.get(key):
        return str(ue_ids[key])
    return None


def _extract_time(entity: Dict) -> Optional[float]:
    """Extract timestamp from a PCAP entity."""
    for key in ["time_epoch", "timestamp", "start_time", "time_start"]:
        val = entity.get(key)
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                pass
    return None


def _level(confidence: int) -> str:
    """Map confidence percentage to level string."""
    if confidence >= 80:
        return "HIGH"
    elif confidence >= 50:
        return "MEDIUM"
    return "LOW"


def _summarize_pcap(event: Dict) -> Dict:
    """Create a brief summary of a PCAP event for the correlation report."""
    return {
        "type": event.get("protocol") or event.get("type") or event.get("procedure_label", "unknown"),
        "time": _extract_time(event),
        "src": event.get("src_ip") or event.get("addr", {}).get("src", ""),
        "dst": event.get("dst_ip") or event.get("addr", {}).get("dst", ""),
    }


def _summarize_gh(event: Dict) -> Dict:
    """Create a brief summary of a Groundhog event for the correlation report."""
    return {
        "event_type": event.get("event_type", ""),
        "event_label": event.get("event_label", ""),
        "time_epoch": event.get("time_epoch"),
        "generation": event.get("generation", ""),
        "cell_id": event.get("cell_id", ""),
    }
