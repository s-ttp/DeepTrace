"""
RAN Analysis Module - Multi-Generation Radio Access Network Analysis

Provides deterministic detection of RAN-related issues across 2G, 3G, 4G, and 5G.
"""
from .extractor import extract_ran_events
from .correlator import build_ue_timelines
from .detectors import detect_ran_issues
from .artifacts import save_ran_artifacts, RanAnalysisResult

__all__ = [
    "analyze_ran",
    "extract_ran_events",
    "build_ue_timelines",
    "detect_ran_issues",
    "save_ran_artifacts",
    "RanAnalysisResult",
]


def analyze_ran(pcap_path: str, artifacts_dir: str = None) -> dict:
    """
    Main entry point for RAN analysis.
    
    Args:
        pcap_path: Path to PCAP file
        artifacts_dir: Optional path to save artifacts (if None, artifacts not saved)
        
    Returns:
        Dictionary with ran_events, ran_timelines, ran_findings, and coverage_flags
    """
    from decode.tshark import tshark_available
    
    if not tshark_available():
        return {
            "ran_events": [],
            "ran_timelines": [],
            "ran_findings": [],
            "coverage_flags": {},
            "error": "TShark not available"
        }
    
    # 1. Extract RAN events from PCAP
    events, coverage_flags = extract_ran_events(pcap_path)
    
    if not events:
        return {
            "ran_events": [],
            "ran_timelines": [],
            "ran_findings": [],
            "coverage_flags": coverage_flags,
            "message": "No RAN traffic observable from this capture point"
        }
    
    # 2. Correlate events into UE timelines
    timelines = build_ue_timelines(events, coverage_flags)
    
    # 3. Detect issues using rule-based engine
    findings = detect_ran_issues(timelines, coverage_flags)
    
    # 4. Save artifacts if directory provided
    if artifacts_dir:
        save_ran_artifacts(artifacts_dir, events, timelines, findings, coverage_flags)
    
    return {
        "ran_events": events,
        "ran_timelines": timelines,
        "ran_findings": findings,
        "coverage_flags": coverage_flags
    }
