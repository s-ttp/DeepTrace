"""
RAN Issue Detectors

Rule-based detection engine for RAN issues.
NO LLM - purely deterministic pattern matching.
"""
import logging
from typing import List, Dict, Any

from .taxonomy import (
    IssueType, Severity, Confidence, 
    RADIO_CAUSE_KEYWORDS, HANDOVER_CAUSE_KEYWORDS, CONGESTION_CAUSE_KEYWORDS
)

logger = logging.getLogger(__name__)


def detect_ran_issues(
    timelines: List[Dict[str, Any]],
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Run all detectors on UE timelines.
    
    Args:
        timelines: List of UE timelines from correlator
        coverage_flags: Protocol coverage flags
        
    Returns:
        List of finding dictionaries
    """
    all_findings = []
    
    for timeline in timelines:
        # Run each detector
        findings = []
        findings.extend(_detect_ue_context_release(timeline, coverage_flags))
        findings.extend(_detect_handover_failure(timeline, coverage_flags))
        findings.extend(_detect_radio_link_failure(timeline, coverage_flags))
        findings.extend(_detect_signaling_congestion(timeline, coverage_flags))
        
        all_findings.extend(findings)
    
    # Global detectors (across all timelines)
    all_findings.extend(_detect_transport_instability(timelines, coverage_flags))
    all_findings.extend(_detect_paging_issues(timelines, coverage_flags))
    
    # Sort by time
    all_findings.sort(key=lambda x: x.get("time_window", {}).get("start", 0))
    
    logger.info(f"Detected {len(all_findings)} RAN issues across {len(timelines)} timelines")
    return all_findings


def _detect_ue_context_release(
    timeline: Dict[str, Any],
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Detect UE Context Release events (4G/5G).
    
    Trigger: procedure_label contains "UEContextRelease"
    Confidence:
    - HIGH if cause indicates radio-related
    - MEDIUM if cause is generic/unknown
    """
    findings = []
    events = timeline.get("events", [])
    generation = timeline.get("generation", "Unknown")
    ue_key = timeline.get("ue_key", "")
    
    # Only applicable for 4G/5G
    if generation not in ["4G", "5G"]:
        return findings
    
    for event in events:
        proc_label = (event.get("procedure_label") or "").lower()
        cause_label = (event.get("cause_label") or "").lower()
        
        # Check for UE Context Release
        if "uecontextrelease" in proc_label.replace(" ", "").replace("_", ""):
            # Determine if radio-related
            is_radio_cause = any(kw in cause_label for kw in RADIO_CAUSE_KEYWORDS)
            
            if is_radio_cause:
                confidence = Confidence.HIGH
                confidence_pct = 90
                severity = Severity.WARNING
                description = f"UE Context Release with radio-related cause: {event.get('cause_label', 'Unknown')}"
            else:
                confidence = Confidence.MEDIUM
                confidence_pct = 70
                severity = Severity.INFO
                description = f"UE Context Release: {event.get('cause_label', 'Unknown cause')}"
            
            findings.append(_build_finding(
                issue_type=IssueType.UE_CONTEXT_RELEASE,
                generation=generation,
                confidence=confidence,
                confidence_pct=confidence_pct,
                severity=severity,
                description=description,
                evidence=[f"Frame {event.get('frame')}: {event.get('procedure_label')} - {event.get('cause_label')}"],
                time_window={"start": event.get("time_epoch", 0), "end": event.get("time_epoch", 0)},
                ue_key=ue_key
            ))
    
    return findings


def _detect_handover_failure(
    timeline: Dict[str, Any],
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Detect Handover Failures.
    
    Trigger: HO request/prep followed by failure or release within 3s
    """
    findings = []
    events = timeline.get("events", [])
    generation = timeline.get("generation", "Unknown")
    ue_key = timeline.get("ue_key", "")
    
    # Find HO preparation/request events
    ho_prep_events = []
    for event in events:
        proc_label = (event.get("procedure_label") or "").lower()
        if any(kw in proc_label for kw in ["handover", "relocation", "pathswitch"]):
            if "preparation" in proc_label or "request" in proc_label or "required" in proc_label:
                ho_prep_events.append(event)
    
    # For each HO prep, look for failure within window
    for prep_event in ho_prep_events:
        prep_time = prep_event.get("time_epoch", 0)
        
        for event in events:
            event_time = event.get("time_epoch", 0)
            time_diff = event_time - prep_time
            
            # Within 3 second window
            if 0 < time_diff <= 3.0:
                proc_label = (event.get("procedure_label") or "").lower()
                cause_label = (event.get("cause_label") or "").lower()
                
                is_failure = (
                    "failure" in proc_label or
                    "cancel" in proc_label or
                    any(kw in cause_label for kw in HANDOVER_CAUSE_KEYWORDS)
                )
                
                is_release_after_ho = (
                    "release" in proc_label and
                    any(kw in cause_label for kw in ["handover", "ho", "relocation"])
                )
                
                if is_failure:
                    findings.append(_build_finding(
                        issue_type=IssueType.HANDOVER_FAILURE,
                        generation=generation,
                        confidence=Confidence.HIGH,
                        confidence_pct=90,
                        severity=Severity.CRITICAL,
                        description=f"Handover failure detected: {event.get('procedure_label')}",
                        evidence=[
                            f"Frame {prep_event.get('frame')}: HO Preparation at {prep_time:.3f}",
                            f"Frame {event.get('frame')}: Failure at {event_time:.3f} - {event.get('cause_label')}"
                        ],
                        time_window={"start": prep_time, "end": event_time},
                        ue_key=ue_key
                    ))
                    break  # Only one finding per prep event
                    
                elif is_release_after_ho:
                    findings.append(_build_finding(
                        issue_type=IssueType.HANDOVER_FAILURE,
                        generation=generation,
                        confidence=Confidence.MEDIUM,
                        confidence_pct=70,
                        description=f"Possible handover failure (release after prep): {event.get('cause_label')}",
                        severity=Severity.WARNING,
                        evidence=[
                            f"Frame {prep_event.get('frame')}: HO Preparation",
                            f"Frame {event.get('frame')}: UE Release with HO-related cause"
                        ],
                        time_window={"start": prep_time, "end": event_time},
                        ue_key=ue_key
                    ))
                    break
    
    return findings


def _detect_radio_link_failure(
    timeline: Dict[str, Any],
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Detect Radio Link Failure (RLF).
    
    Trigger: cause_label explicitly mentions RLF keywords
    """
    findings = []
    events = timeline.get("events", [])
    generation = timeline.get("generation", "Unknown")
    ue_key = timeline.get("ue_key", "")
    
    for event in events:
        cause_label = (event.get("cause_label") or "").lower()
        
        # Check for explicit RLF indication
        is_rlf = any(kw in cause_label for kw in ["radio link failure", "rlf", "radio connection"])
        
        if is_rlf:
            findings.append(_build_finding(
                issue_type=IssueType.RADIO_LINK_FAILURE,
                generation=generation,
                confidence=Confidence.HIGH,
                confidence_pct=95,
                severity=Severity.CRITICAL,
                description=f"Radio Link Failure detected: {event.get('cause_label')}",
                evidence=[f"Frame {event.get('frame')}: {event.get('procedure_label')} - {event.get('cause_label')}"],
                time_window={"start": event.get("time_epoch", 0), "end": event.get("time_epoch", 0)},
                ue_key=ue_key
            ))
    
    return findings


def _detect_signaling_congestion(
    timeline: Dict[str, Any],
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Detect signaling congestion (excessive procedures in short time).
    
    Trigger: >10 procedures per UE within 5 seconds
    """
    findings = []
    events = timeline.get("events", [])
    generation = timeline.get("generation", "Unknown")
    ue_key = timeline.get("ue_key", "")
    
    if len(events) < 10:
        return findings
    
    # Sliding window analysis
    window_size = 5.0  # seconds
    threshold = 10  # events
    
    for i, start_event in enumerate(events):
        start_time = start_event.get("time_epoch", 0)
        window_events = []
        
        for event in events[i:]:
            event_time = event.get("time_epoch", 0)
            if event_time - start_time <= window_size:
                window_events.append(event)
            else:
                break
        
        if len(window_events) >= threshold:
            # Check for congestion-related causes
            has_congestion_cause = any(
                any(kw in (e.get("cause_label") or "").lower() for kw in CONGESTION_CAUSE_KEYWORDS)
                for e in window_events
            )
            
            confidence = Confidence.HIGH if has_congestion_cause else Confidence.MEDIUM
            confidence_pct = 85 if has_congestion_cause else 65
            
            findings.append(_build_finding(
                issue_type=IssueType.SIGNALING_CONGESTION,
                generation=generation,
                confidence=confidence,
                confidence_pct=confidence_pct,
                severity=Severity.WARNING,
                description=f"Signaling congestion: {len(window_events)} events in {window_size}s window",
                evidence=[f"Frames {window_events[0].get('frame')} to {window_events[-1].get('frame')}"],
                time_window={"start": start_time, "end": window_events[-1].get("time_epoch", 0)},
                ue_key=ue_key
            ))
            
            # Only report once per timeline
            break
    
    return findings


def _detect_transport_instability(
    timelines: List[Dict[str, Any]],
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Detect SCTP transport instability across all events.
    
    Trigger: SCTP ABORT or high retransmission rate
    """
    findings = []
    
    if not coverage_flags.get("has_sctp"):
        return findings
    
    # Collect all SCTP events
    sctp_events = []
    for timeline in timelines:
        for event in timeline.get("events", []):
            if event.get("protocol") == "SCTP":
                sctp_events.append(event)
    
    if not sctp_events:
        return findings
    
    # Check for ABORT chunks (chunk_type = 6)
    abort_events = [e for e in sctp_events if e.get("transport", {}).get("chunk_type") == "6"]
    
    if abort_events:
        findings.append(_build_finding(
            issue_type=IssueType.TRANSPORT_INSTABILITY,
            generation="Transport",
            confidence=Confidence.HIGH,
            confidence_pct=90,
            severity=Severity.CRITICAL,
            description=f"SCTP ABORT detected ({len(abort_events)} events)",
            evidence=[f"Frame {e.get('frame')}" for e in abort_events[:5]],
            time_window={
                "start": min(e.get("time_epoch", 0) for e in abort_events),
                "end": max(e.get("time_epoch", 0) for e in abort_events)
            },
            ue_key="transport_global"
        ))
    
    # Check for high retransmission
    retrans_events = [e for e in sctp_events if e.get("transport", {}).get("retransmission")]
    if len(retrans_events) > 5:
        findings.append(_build_finding(
            issue_type=IssueType.TRANSPORT_INSTABILITY,
            generation="Transport",
            confidence=Confidence.MEDIUM,
            confidence_pct=70,
            severity=Severity.WARNING,
            description=f"High SCTP retransmission rate ({len(retrans_events)} retrans)",
            evidence=[f"Frame {e.get('frame')}" for e in retrans_events[:5]],
            time_window={
                "start": min(e.get("time_epoch", 0) for e in retrans_events),
                "end": max(e.get("time_epoch", 0) for e in retrans_events)
            },
            ue_key="transport_global"
        ))
    
    return findings


def _detect_paging_issues(
    timelines: List[Dict[str, Any]],
    coverage_flags: Dict[str, bool]
) -> List[Dict[str, Any]]:
    """
    Detect paging failures (paging without subsequent setup).
    
    Note: This is a best-effort detector; paging success may not be observable.
    """
    findings = []
    
    # Collect paging events
    paging_events = []
    for timeline in timelines:
        for event in timeline.get("events", []):
            proc_label = (event.get("procedure_label") or "").lower()
            if "paging" in proc_label:
                paging_events.append(event)
    
    if not paging_events:
        return findings
    
    # For now, just report paging count as info
    # Full detection would require correlating with session setup success
    if len(paging_events) > 10:
        findings.append(_build_finding(
            issue_type=IssueType.PAGING_FAILURE,
            generation="Mixed",
            confidence=Confidence.LOW,
            confidence_pct=40,
            severity=Severity.INFO,
            description=f"High paging activity ({len(paging_events)} paging events) - may indicate UE reachability issues",
            evidence=[f"Frame {e.get('frame')}" for e in paging_events[:5]],
            time_window={
                "start": min(e.get("time_epoch", 0) for e in paging_events),
                "end": max(e.get("time_epoch", 0) for e in paging_events)
            },
            ue_key="paging_global"
        ))
    
    return findings


def _build_finding(
    issue_type: IssueType,
    generation: str,
    confidence: Confidence,
    confidence_pct: int,
    severity: Severity,
    description: str,
    evidence: List[str],
    time_window: Dict[str, float],
    ue_key: str
) -> Dict[str, Any]:
    """Build a standardized finding dictionary"""
    return {
        "type": issue_type.value,
        "generation": generation,
        "confidence": confidence.value,
        "confidence_pct": confidence_pct,
        "severity": severity.value,
        "description": description,
        "evidence": evidence,
        "time_window": time_window,
        "ue_key": ue_key
    }
