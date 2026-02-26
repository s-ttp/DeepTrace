"""
Main Correlation Orchestrator.

Loads PCAP and Groundhog artifacts, runs scoring, builds timeline,
and writes correlation reports.
"""
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

from .scoring import find_correlations
from .cross_plane_events import build_cross_plane_timeline

logger = logging.getLogger(__name__)


def run_correlation(
    case_dir: str,
    pcap_events: List[Dict[str, Any]] = None,
    groundhog_events: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run cross-plane correlation between PCAP and Groundhog data.
    
    Args:
        case_dir: Path to case directory (artifacts/<case_id>/)
        pcap_events: Pre-loaded PCAP events (or loaded from case_dir/pcap/)
        groundhog_events: Pre-loaded Groundhog events (or loaded from case_dir/groundhog/)
        
    Returns:
        Dict with cross_plane_events, correlation_report
    """
    case_path = Path(case_dir)
    
    # Load PCAP events if not provided
    if pcap_events is None:
        pcap_events = _load_pcap_events(case_path)
    
    # Load Groundhog events if not provided
    if groundhog_events is None:
        groundhog_events = _load_groundhog_events(case_path)
    
    if not pcap_events and not groundhog_events:
        return {
            "cross_plane_events": [],
            "correlation_report": {
                "status": "NO_DATA",
                "message": "No PCAP or Groundhog data available for correlation",
            }
        }
    
    if not pcap_events:
        return {
            "cross_plane_events": _build_gh_only_timeline(groundhog_events),
            "correlation_report": {
                "status": "GROUNDHOG_ONLY",
                "message": "Only Groundhog data available. Upload PCAP for cross-plane correlation.",
                "groundhog_event_count": len(groundhog_events),
            }
        }
    
    if not groundhog_events:
        return {
            "cross_plane_events": _build_pcap_only_timeline(pcap_events),
            "correlation_report": {
                "status": "PCAP_ONLY",
                "message": "Only PCAP data available. Upload Groundhog trace for radio correlation.",
                "pcap_event_count": len(pcap_events),
            }
        }
    
    # Both datasets available — run full correlation
    logger.info(f"Running correlation: {len(pcap_events)} PCAP events, {len(groundhog_events)} Groundhog events")
    
    # 1. Build cross-plane timeline
    timeline = build_cross_plane_timeline(pcap_events, groundhog_events)
    
    # 2. Find identity/time correlations
    correlations = find_correlations(pcap_events, groundhog_events, min_confidence=30)
    
    # 3. Determine time alignment
    pcap_times = [_get_time(e) for e in pcap_events if _get_time(e)]
    gh_times = [e["time_epoch"] for e in groundhog_events if e.get("time_epoch")]
    
    time_alignment = "UNKNOWN"
    overlap_seconds = 0
    if pcap_times and gh_times:
        pcap_start, pcap_end = min(pcap_times), max(pcap_times)
        gh_start, gh_end = min(gh_times), max(gh_times)
        
        overlap_start = max(pcap_start, gh_start)
        overlap_end = min(pcap_end, gh_end)
        overlap_seconds = max(0, overlap_end - overlap_start)
        
        if overlap_seconds > 0:
            time_alignment = "OVERLAPPING"
        elif abs(pcap_start - gh_start) < 3600:
            time_alignment = "CLOSE"
        else:
            time_alignment = "DISJOINT"
    
    # 4. Identify key correlated incidents
    key_incidents = _identify_key_incidents(correlations, groundhog_events, pcap_events)
    
    # 5. Build report
    report = {
        "status": "CORRELATED",
        "pcap_event_count": len(pcap_events),
        "groundhog_event_count": len(groundhog_events),
        "total_correlations": len(correlations),
        "high_confidence_matches": sum(1 for c in correlations if c["confidence_pct"] >= 80),
        "medium_confidence_matches": sum(1 for c in correlations if 50 <= c["confidence_pct"] < 80),
        "low_confidence_matches": sum(1 for c in correlations if c["confidence_pct"] < 50),
        "time_alignment": time_alignment,
        "overlap_seconds": round(overlap_seconds, 1),
        "matched_identifiers": _collect_matched_ids(correlations),
        "key_incidents": key_incidents,
        "correlations": correlations[:50],  # Top 50
    }
    
    # 6. Save artifacts
    corr_dir = case_path / "correlation"
    corr_dir.mkdir(parents=True, exist_ok=True)
    
    with open(corr_dir / "cross_plane_events.json", "w") as f:
        json.dump(timeline, f, indent=2, default=str)
    
    with open(corr_dir / "correlation_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"Correlation complete: {len(correlations)} matches, alignment={time_alignment}")
    
    return {
        "cross_plane_events": timeline,
        "correlation_report": report,
    }


def _load_pcap_events(case_path: Path) -> List[Dict[str, Any]]:
    """Load PCAP-derived events from case artifacts."""
    events = []
    pcap_dir = case_path / "pcap"
    
    # Load flows
    flows_path = pcap_dir / "flows.json"
    if flows_path.exists():
        with open(flows_path) as f:
            events.extend(json.load(f))
    
    # Load expert findings
    findings_path = pcap_dir / "expert_findings.json"
    if findings_path.exists():
        with open(findings_path) as f:
            events.extend(json.load(f))
    
    # Load RAN findings
    ran_path = pcap_dir / "ran_findings.json"
    if ran_path.exists():
        with open(ran_path) as f:
            events.extend(json.load(f))
    
    return events


def _load_groundhog_events(case_path: Path) -> List[Dict[str, Any]]:
    """Load normalized Groundhog events from case artifacts."""
    gh_path = case_path / "groundhog" / "normalized_radio_events.json"
    if gh_path.exists():
        with open(gh_path) as f:
            return json.load(f)
    return []


def _get_time(entity: Dict) -> Optional[float]:
    """Extract time from various entity formats."""
    for key in ["time_epoch", "timestamp", "start_time", "time_start"]:
        if entity.get(key) is not None:
            try:
                return float(entity[key])
            except (ValueError, TypeError):
                continue
    return None


def _collect_matched_ids(correlations: List[Dict]) -> Dict[str, list]:
    """Collect unique matched identifiers from correlations."""
    ids = {"IMSI": set(), "GUTI": set(), "TMSI": set(), "UE_IP": set(), "CELL_ID": set()}
    for corr in correlations:
        for match_type, value in corr.get("matched_keys", []):
            if match_type in ids:
                ids[match_type].add(value)
    return {k: list(v) for k, v in ids.items() if v}


def _identify_key_incidents(
    correlations: List[Dict],
    gh_events: List[Dict],
    pcap_events: List[Dict],
) -> List[Dict]:
    """Identify significant correlated incidents (e.g., RLF near call failure)."""
    incidents = []
    
    for corr in correlations:
        gh_ev = corr.get("groundhog_event", {})
        pcap_ev = corr.get("pcap_event", {})
        
        gh_type = gh_ev.get("event_type", "").upper()
        pcap_type = pcap_ev.get("type", "").upper()
        time_delta = corr.get("time_delta_seconds")
        
        # RLF near SIP/call failure
        if gh_type == "RLF" and time_delta and time_delta <= 5:
            incidents.append({
                "type": "RLF_NEAR_CALL_EVENT",
                "description": f"Radio Link Failure within {time_delta:.1f}s of {pcap_type}",
                "severity": "critical",
                "confidence": corr["confidence_pct"],
            })
        
        # HO failure near call event
        if gh_type == "HO_FAIL" and time_delta and time_delta <= 5:
            incidents.append({
                "type": "HO_FAIL_NEAR_CALL",
                "description": f"Handover Failure within {time_delta:.1f}s of {pcap_type}",
                "severity": "critical",
                "confidence": corr["confidence_pct"],
            })
        
        # Paging failure
        if gh_type == "PAGING" and time_delta and time_delta <= 10:
            incidents.append({
                "type": "PAGING_NEAR_CALL",
                "description": f"Paging event within {time_delta:.1f}s of {pcap_type}",
                "severity": "warning",
                "confidence": corr["confidence_pct"],
            })
    
    return incidents[:20]  # Top 20


def _build_gh_only_timeline(events: List[Dict]) -> List[Dict]:
    """Build timeline from Groundhog events only."""
    return [
        {
            "time_epoch": ev.get("time_epoch"),
            "source": "GROUNDHOG",
            "event_type": ev.get("event_type", "UNKNOWN"),
            "description": ev.get("event_label", ""),
            "severity": "info",
            "details": {
                "generation": ev.get("generation", ""),
                "cell_id": ev.get("cell_id", ""),
            },
        }
        for ev in events if ev.get("time_epoch")
    ]


def _build_pcap_only_timeline(events: List[Dict]) -> List[Dict]:
    """Build timeline from PCAP events only."""
    timeline = []
    for ev in events:
        t = _get_time(ev)
        if t:
            timeline.append({
                "time_epoch": t,
                "source": "PCAP",
                "event_type": ev.get("protocol", "unknown"),
                "description": ev.get("procedure_label", ""),
                "severity": ev.get("severity", "info"),
                "details": {},
            })
    return sorted(timeline, key=lambda x: x["time_epoch"])
