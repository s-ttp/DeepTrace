"""
RAN Analysis Artifacts

Saves analysis results to JSON files.
"""
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class RanAnalysisResult:
    """Container for RAN analysis results"""
    events: List[Dict[str, Any]]
    timelines: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    coverage_flags: Dict[str, bool]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def save_ran_artifacts(
    artifacts_dir: str,
    events: List[Dict[str, Any]],
    timelines: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    coverage_flags: Dict[str, bool]
) -> None:
    """
    Save RAN analysis artifacts to disk.
    
    Creates:
    - ran_events.json
    - ran_timelines.json
    - ran_findings.json
    
    Args:
        artifacts_dir: Directory to save artifacts
        events: Normalized RAN events
        timelines: UE timelines
        findings: Detected issues
        coverage_flags: Protocol coverage
    """
    path = Path(artifacts_dir)
    path.mkdir(parents=True, exist_ok=True)
    
    try:
        # Save events
        with open(path / "ran_events.json", "w") as f:
            json.dump(events, f, indent=2, default=str)
        
        # Save timelines (limit event details for size)
        timelines_export = []
        for timeline in timelines:
            export = {
                "ue_key": timeline.get("ue_key"),
                "generation": timeline.get("generation"),
                "protocols": timeline.get("protocols"),
                "event_count": timeline.get("event_count"),
                "time_start": timeline.get("time_start"),
                "time_end": timeline.get("time_end"),
                "duration": timeline.get("duration"),
                # Include limited events for context
                "events_sample": timeline.get("events", [])[:10]
            }
            timelines_export.append(export)
        
        with open(path / "ran_timelines.json", "w") as f:
            json.dump(timelines_export, f, indent=2, default=str)
        
        # Save findings
        with open(path / "ran_findings.json", "w") as f:
            json.dump(findings, f, indent=2, default=str)
        
        logger.info(f"Saved RAN artifacts to {path}")
        
    except Exception as e:
        logger.error(f"Failed to save RAN artifacts: {e}")


def format_findings_for_llm(findings: List[Dict[str, Any]], coverage_flags: Dict[str, bool]) -> str:
    """
    Format RAN findings for LLM context.
    
    Returns markdown-formatted string for inclusion in LLM prompt.
    """
    if not findings:
        # Check if we even had RAN data
        has_ran = any([
            coverage_flags.get("has_s1ap"),
            coverage_flags.get("has_ngap"),
            coverage_flags.get("has_ranap"),
            coverage_flags.get("has_bssap"),
        ])
        
        if not has_ran:
            return "## RAN ANALYSIS\nNo RAN signaling (S1AP/NGAP/RANAP/BSSAP) observable from this capture point."
        else:
            return "## RAN ANALYSIS\nRAN signaling present but no issues detected."
    
    lines = ["## RAN ANALYSIS (DETERMINISTIC)", ""]
    lines.append(f"**Total Findings:** {len(findings)}")
    lines.append("")
    
    # Group by severity
    critical = [f for f in findings if f.get("severity") == "critical"]
    warning = [f for f in findings if f.get("severity") == "warning"]
    info = [f for f in findings if f.get("severity") == "info"]
    
    if critical:
        lines.append("### Critical Issues")
        for f in critical:
            lines.append(f"- **{f.get('type')}** ({f.get('generation')}): {f.get('description')}")
            lines.append(f"  - Confidence: {f.get('confidence')} ({f.get('confidence_pct')}%)")
            lines.append(f"  - Evidence: {', '.join(f.get('evidence', [])[:3])}")
        lines.append("")
    
    if warning:
        lines.append("### Warnings")
        for f in warning:
            lines.append(f"- **{f.get('type')}** ({f.get('generation')}): {f.get('description')}")
            lines.append(f"  - Evidence: {', '.join(f.get('evidence', [])[:2])}")
        lines.append("")
    
    if info:
        lines.append("### Observations")
        for f in info:
            lines.append(f"- {f.get('type')}: {f.get('description')}")
        lines.append("")
    
    # Coverage summary
    lines.append("### Protocol Coverage")
    coverage_items = []
    if coverage_flags.get("has_4g"):
        coverage_items.append("4G (S1AP)")
    if coverage_flags.get("has_5g"):
        coverage_items.append("5G (NGAP)")
    if coverage_flags.get("has_3g"):
        coverage_items.append("3G (RANAP)")
    if coverage_flags.get("has_2g"):
        coverage_items.append("2G (BSSAP)")
    
    lines.append(f"Detected: {', '.join(coverage_items) if coverage_items else 'None'}")
    
    return "\n".join(lines)
