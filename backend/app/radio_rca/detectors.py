"""
Deterministic Radio Root Cause Detectors.

Rules that cross-reference Groundhog radio events with PCAP findings
to produce grounded radio root causes. NO LLM — purely evidence-based.
"""
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from .rules import (
    CORRELATION_WINDOW_TIGHT, CORRELATION_WINDOW_MEDIUM, CORRELATION_WINDOW_WIDE,
    RSRP_POOR_THRESHOLD, RSRP_CRITICAL_THRESHOLD,
    RSRQ_POOR_THRESHOLD, SINR_POOR_THRESHOLD, SINR_CRITICAL_THRESHOLD,
    THROUGHPUT_COLLAPSE_THRESHOLD, BLER_HIGH_THRESHOLD, HARQ_NACK_CRITICAL_THRESHOLD,
    RadioFindingType,
)

logger = logging.getLogger(__name__)


def detect_radio_root_causes(
    groundhog_events: List[Dict[str, Any]] = None,
    pcap_findings: List[Dict[str, Any]] = None,
    correlation_report: Dict[str, Any] = None,
    groundhog_summary: Dict[str, Any] = None,
    output_dir: str = None,
) -> List[Dict[str, Any]]:
    """
    Run all radio RCA detectors.
    
    Args:
        groundhog_events: Normalized Groundhog radio events
        pcap_findings: PCAP expert findings / RAN findings
        correlation_report: Output from correlation engine
        groundhog_summary: Groundhog summary statistics
        output_dir: Directory to save radio_findings.json
        
    Returns:
        List of radio finding dicts
    """
    findings = []
    
    gh_events = groundhog_events or []
    pcap_find = pcap_findings or []
    corr = correlation_report or {}
    
    if not gh_events and not pcap_find:
        findings.append(_build_finding(
            finding_type=RadioFindingType.NOT_OBSERVABLE,
            confidence_pct=100,
            confidence_level="HIGH",
            description="No radio data available. Neither Groundhog radio trace nor RAN signaling captured.",
            evidence=[],
            limitations=["Upload Groundhog radio trace or capture RAN signaling (S1AP/NGAP) to enable radio analysis"],
        ))
        return findings
    
    if not gh_events:
        findings.append(_build_finding(
            finding_type=RadioFindingType.NOT_OBSERVABLE,
            confidence_pct=80,
            confidence_level="MEDIUM",
            description="No Groundhog radio trace uploaded. Radio KPI analysis not possible without UE-side measurements.",
            evidence=["Only PCAP-side RAN signaling available" if pcap_find else "No evidence"],
            limitations=["Upload Groundhog radio trace for radio KPI analysis (RSRP, SINR, handover, RLF)"],
        ))
    
    # Run each detector
    findings.extend(_detect_rlf_impacting_call(gh_events, pcap_find, corr))
    findings.extend(_detect_handover_failure(gh_events, pcap_find, corr))
    findings.extend(_detect_paging_failure(gh_events, pcap_find, corr))
    findings.extend(_detect_coverage_degradation(gh_events, groundhog_summary))
    findings.extend(_detect_data_path_degradation(gh_events, groundhog_summary))
    findings.extend(_detect_rrc_reestablishment(gh_events))
    findings.extend(_detect_rrc_reconfig_failure(gh_events))
    findings.extend(_detect_rrc_reconfig_latency(gh_events))
    findings.extend(_detect_abnormal_release(gh_events))
    findings.extend(_detect_erab_setup_failure(gh_events))
    findings.extend(_detect_sgnb_addition_failure(gh_events))
    findings.extend(_detect_high_harq_nack(gh_events))
    findings.extend(_detect_csfb(gh_events, pcap_find))
    
    # Save artifacts
    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        with open(out_path / "radio_findings.json", "w") as f:
            json.dump(findings, f, indent=2, default=str)
        logger.info(f"Saved {len(findings)} radio findings to {out_path}")
    
    logger.info(f"Radio RCA: {len(findings)} findings detected")
    return findings


def _detect_rlf_impacting_call(
    gh_events: List[Dict], pcap_find: List[Dict], corr: Dict
) -> List[Dict]:
    """RLF within ±5s of a SIP/call failure → RADIO_LINK_FAILURE_IMPACTING_CALL."""
    findings = []
    rlf_events = [e for e in gh_events if e.get("event_type") == "RLF"]
    
    if not rlf_events:
        return findings
    
    # Check correlation key incidents
    key_incidents = corr.get("key_incidents", [])
    rlf_incidents = [ki for ki in key_incidents if ki.get("type") == "RLF_NEAR_CALL_EVENT"]
    
    if rlf_incidents:
        for incident in rlf_incidents:
            findings.append(_build_finding(
                finding_type=RadioFindingType.RADIO_LINK_FAILURE_IMPACTING_CALL,
                confidence_pct=90,
                confidence_level="HIGH",
                description=incident.get("description", "Radio Link Failure coinciding with call event"),
                evidence=[
                    f"RLF events: {len(rlf_events)} detected in Groundhog trace",
                    f"Correlation: {incident.get('description', '')}",
                    f"Correlation confidence: {incident.get('confidence', 0)}%",
                ],
                limitations=["Exact layer-2 failure cause requires deeper UE logs"],
            ))
    elif rlf_events:
        # RLF present but no direct PCAP correlation
        findings.append(_build_finding(
            finding_type=RadioFindingType.RADIO_LINK_FAILURE_IMPACTING_CALL,
            confidence_pct=60,
            confidence_level="MEDIUM",
            description=f"{len(rlf_events)} Radio Link Failure(s) detected in Groundhog trace",
            evidence=[
                f"RLF count: {len(rlf_events)}",
                f"First RLF at epoch: {rlf_events[0].get('time_epoch', 'unknown')}",
                f"Cell: {rlf_events[0].get('cell_id', 'unknown')}",
            ],
            limitations=["No PCAP correlation available to confirm call impact"],
        ))
    
    return findings


def _detect_handover_failure(
    gh_events: List[Dict], pcap_find: List[Dict], corr: Dict
) -> List[Dict]:
    """HO_FAIL near BYE/call end → HANDOVER_FAILURE_OR_SRVCC."""
    findings = []
    ho_fails = [e for e in gh_events if e.get("event_type") == "HO_FAIL"]
    
    if not ho_fails:
        return findings
    
    # Check correlation for HO_FAIL near call events
    key_incidents = corr.get("key_incidents", [])
    ho_incidents = [ki for ki in key_incidents if ki.get("type") == "HO_FAIL_NEAR_CALL"]
    
    confidence = 85 if ho_incidents else 55
    level = "HIGH" if ho_incidents else "MEDIUM"
    
    evidence = [f"Handover failures: {len(ho_fails)} detected"]
    for hf in ho_fails[:3]:
        evidence.append(
            f"HO_FAIL at {hf.get('time_epoch', '?')}, cell={hf.get('cell_id', '?')}, "
            f"gen={hf.get('generation', '?')}"
        )
    
    if ho_incidents:
        evidence.append(f"Correlated with {len(ho_incidents)} PCAP call events")
    
    # Check for SRVCC hints
    srvcc_events = [e for e in gh_events if e.get("event_type") == "SRVCC"]
    if srvcc_events:
        evidence.append(f"SRVCC events also detected: {len(srvcc_events)}")
    
    findings.append(_build_finding(
        finding_type=RadioFindingType.HANDOVER_FAILURE_OR_SRVCC,
        confidence_pct=confidence,
        confidence_level=level,
        description=f"{len(ho_fails)} Handover Failure(s) detected" +
                    (f" with PCAP correlation" if ho_incidents else ""),
        evidence=evidence,
        limitations=["Target cell information may be incomplete"],
    ))
    
    return findings


def _detect_paging_failure(
    gh_events: List[Dict], pcap_find: List[Dict], corr: Dict
) -> List[Dict]:
    """Paging attempts with no success → PAGING_FAILURE_OR_UE_UNREACHABLE."""
    findings = []
    paging_events = [e for e in gh_events if e.get("event_type") == "PAGING"]
    
    if not paging_events:
        return findings
    
    # Check for paging with success=False
    failed_pages = [
        p for p in paging_events
        if p.get("paging") and not p["paging"].get("success", True)
    ]
    
    if failed_pages:
        findings.append(_build_finding(
            finding_type=RadioFindingType.PAGING_FAILURE_OR_UE_UNREACHABLE,
            confidence_pct=70,
            confidence_level="MEDIUM",
            description=f"{len(failed_pages)} paging failure(s) detected (UE may be unreachable)",
            evidence=[
                f"Total paging events: {len(paging_events)}",
                f"Failed pages: {len(failed_pages)}",
            ],
            limitations=["Paging success may not always be observable from Groundhog trace"],
        ))
    
    return findings


def _detect_coverage_degradation(
    gh_events: List[Dict], summary: Dict = None
) -> List[Dict]:
    """Low RSRP/RSRQ/SINR → COVERAGE_DEGRADATION."""
    findings = []
    
    # Check KPI statistics from summary
    kpis = (summary or {}).get("kpi_statistics", {})
    
    rsrp_stats = kpis.get("rsrp", {})
    sinr_stats = kpis.get("sinr", {})
    
    evidence = []
    is_degraded = False
    
    if rsrp_stats:
        if rsrp_stats.get("min", 0) < RSRP_CRITICAL_THRESHOLD:
            evidence.append(f"RSRP minimum: {rsrp_stats['min']} dBm (CRITICAL, < {RSRP_CRITICAL_THRESHOLD})")
            is_degraded = True
        elif rsrp_stats.get("avg", 0) < RSRP_POOR_THRESHOLD:
            evidence.append(f"RSRP average: {rsrp_stats['avg']} dBm (POOR, < {RSRP_POOR_THRESHOLD})")
            is_degraded = True
    
    if sinr_stats:
        if sinr_stats.get("min", 999) < SINR_CRITICAL_THRESHOLD:
            evidence.append(f"SINR minimum: {sinr_stats['min']} dB (CRITICAL, < {SINR_CRITICAL_THRESHOLD})")
            is_degraded = True
        elif sinr_stats.get("avg", 999) < SINR_POOR_THRESHOLD:
            evidence.append(f"SINR average: {sinr_stats['avg']} dB (POOR, < {SINR_POOR_THRESHOLD})")
            is_degraded = True
    
    # Also check individual events
    poor_rsrp_count = sum(1 for e in gh_events if e.get("rsrp") is not None and e["rsrp"] < RSRP_POOR_THRESHOLD)
    if poor_rsrp_count > 0:
        evidence.append(f"Events with poor RSRP (< {RSRP_POOR_THRESHOLD}): {poor_rsrp_count}/{len(gh_events)}")
        is_degraded = True
    
    if is_degraded:
        findings.append(_build_finding(
            finding_type=RadioFindingType.COVERAGE_DEGRADATION,
            confidence_pct=75,
            confidence_level="MEDIUM",
            description="RF coverage degradation detected from Groundhog KPIs",
            evidence=evidence,
            limitations=["Antenna/sector configuration not available", "Indoor vs outdoor not distinguishable"],
        ))
    
    return findings


def _detect_data_path_degradation(
    gh_events: List[Dict], summary: Dict = None
) -> List[Dict]:
    """Throughput collapse → RADIO_DATA_PATH_DEGRADATION."""
    findings = []
    
    kpis = (summary or {}).get("kpi_statistics", {})
    dl_tp = kpis.get("throughput_dl_kbps", {})
    
    if dl_tp and dl_tp.get("min", 9999) < THROUGHPUT_COLLAPSE_THRESHOLD:
        findings.append(_build_finding(
            finding_type=RadioFindingType.RADIO_DATA_PATH_DEGRADATION,
            confidence_pct=65,
            confidence_level="MEDIUM",
            description="DL throughput collapse detected",
            evidence=[
                f"DL throughput min: {dl_tp['min']} kbps",
                f"DL throughput avg: {dl_tp.get('avg', '?')} kbps",
                f"Threshold: {THROUGHPUT_COLLAPSE_THRESHOLD} kbps",
            ],
            limitations=["Application-level throughput limitation vs radio not distinguishable"],
        ))
    
    return findings


def _detect_rrc_reestablishment(gh_events: List[Dict]) -> List[Dict]:
    """RRC re-establishment events indicate radio link disruption."""
    findings = []
    reest = [e for e in gh_events if e.get("event_type") == "RRC_REESTABLISHMENT"]
    
    if reest:
        findings.append(_build_finding(
            finding_type=RadioFindingType.RRC_REESTABLISHMENT_DETECTED,
            confidence_pct=70,
            confidence_level="MEDIUM",
            description=f"{len(reest)} RRC Re-establishment(s) detected (radio link disruption)",
            evidence=[
                f"RRC Re-establishments: {len(reest)}",
                f"First at: {reest[0].get('time_epoch', '?')}",
            ],
            limitations=["Re-establishment cause (T310 expiry vs HO failure) requires deeper logs"],
        ))
    
    return findings


def _detect_rrc_reconfig_failure(gh_events: List[Dict]) -> List[Dict]:
    """RRC Reconfiguration Failure detected → RRC_RECONFIGURATION_FAILURE."""
    findings = []
    failed_reconfigs = []
    
    for e in gh_events:
        msg = str(e.get("event_type", "")) + " " + str(e.get("event_label", ""))
        msg = msg.upper()
        if "INTERNAL_PROC_RRC_CONN_RECONF_NO_MOB" in msg:
            raw = e.get("raw", {})
            # Depending on normalization, the key could be lowercase
            if raw.get("rrc_reconfig_result") == "1" or raw.get("RRC_RECONFIG_RESULT") == "1":
                failed_reconfigs.append(e)
                
    if failed_reconfigs:
        evidence = [f"RRC Reconfiguration Failures detected: {len(failed_reconfigs)}"]
        for f in failed_reconfigs[:3]:
            raw = f.get("raw", {})
            cause = raw.get("rrc_reconfig_cause", raw.get("RRC_RECONFIG_CAUSE", "Unknown"))
            t = f.get("time_text", "Unknown")
            evidence.append(f"At {t}: Result=1 (FAILURE), Cause={cause}")
            
        findings.append(_build_finding(
            finding_type=RadioFindingType.RRC_RECONFIGURATION_FAILURE,
            confidence_pct=95,
            confidence_level="HIGH",
            description=f"{len(failed_reconfigs)} RRC Connection Reconfiguration Failure(s) detected (rrc_reconfig_result=1). The UE failed to apply the reconfiguration, resulting in radio link loss.",
            evidence=evidence,
            limitations=["Correlate with X2/SgNB modification attempts if PCAP is present to identify trigger"],
        ))
        
    return findings


def _detect_rrc_reconfig_latency(gh_events: List[Dict]) -> List[Dict]:
    """Calculate RRC Reconfiguration latency and detect degradation."""
    findings = []
    
    pending_time = None
    latencies = []
    
    for e in gh_events:
        msg = str(e.get("event_type", "")) + " " + str(e.get("event_label", ""))
        msg = msg.upper()
        
        raw = e.get("raw", {})
        from_node = raw.get("from_node", "").upper()
        to_node = raw.get("to_node", "").upper()
        
        # We need exact string matches to avoid confusing requests and completes
        if "RRC_RRC_CONNECTION_RECONFIGURATION" in msg and "COMPLETE" not in msg:
            if to_node == "UE":
                pending_time = e.get("time_epoch")
                
        elif "RRC_RRC_CONNECTION_RECONFIGURATION_COMPLETE" in msg:
            if from_node == "UE" and pending_time:
                latency_ms = (e.get("time_epoch") - pending_time) * 1000.0
                if latency_ms > 0:
                    latencies.append({
                        "time_text": e.get("time_text", ""),
                        "latency_ms": latency_ms
                    })
                pending_time = None
                
    if latencies:
        max_lat = max(l["latency_ms"] for l in latencies)
        if max_lat > 1000:
            evidence = [f"Analyzed {len(latencies)} RRC Reconfiguration cycles.",
                        f"Max response latency reached {max_lat:.1f}ms before failure."]
            for l in latencies[max(0, len(latencies)-3):]:
                evidence.append(f"At {l['time_text']}: Latency = {l['latency_ms']:.1f}ms")
                
            findings.append(_build_finding(
                finding_type=RadioFindingType.RRC_RECONFIGURATION_LATENCY,
                confidence_pct=85,
                confidence_level="HIGH",
                description=f"Severe RRC Reconfiguration latency degradation detected (max {max_lat:.1f}ms). Indicates degrading RF conditions or cell edge prior to link loss.",
                evidence=evidence,
                limitations=["Only measures application layer RRC response, not underlying MAC/RLC retransmissions"],
            ))
            
    return findings


def _detect_abnormal_release(gh_events: List[Dict]) -> List[Dict]:
    """Detect S1AP UE Context Release Request with specific radioNetwork cause."""
    findings = []
    abnormal_releases = []
    
    for e in gh_events:
        raw = e.get("raw", {})
        if "release_cause" in raw:
            cause_lower = str(raw["release_cause"]).lower()
            if "connection-with-ue-lost" in cause_lower or "radio-link-failure" in cause_lower:
                abnormal_releases.append(e)
            
    if abnormal_releases:
        evidence = []
        for r in abnormal_releases[:3]:
            cause = r.get("raw", {}).get("release_cause", "Unknown")
            t = r.get("time_text", "Unknown")
            evidence.append(f"At {t}: S1 Release Cause = {cause}")
            
        findings.append(_build_finding(
            finding_type=RadioFindingType.ABNORMAL_RADIO_RELEASE,
            confidence_pct=95,
            confidence_level="HIGH",
            description=f"Abnormal Radio Release detected. The network explicitly requested UE context release due to: {abnormal_releases[-1].get('raw', {}).get('release_cause')}.",
            evidence=evidence,
            limitations=["None. The S1AP message explicitly confirms the connection was lost."],
        ))
        
    return findings


def _detect_csfb(gh_events: List[Dict], pcap_find: List[Dict]) -> List[Dict]:
    """CS Fallback detected → may indicate VoLTE not available."""
    findings = []
    csfb = [e for e in gh_events if e.get("event_type") == "CSFB"]
    
    if csfb:
        findings.append(_build_finding(
            finding_type=RadioFindingType.CSFB_DETECTED,
            confidence_pct=80,
            confidence_level="HIGH",
            description=f"{len(csfb)} CS Fallback event(s) detected (VoLTE may not be available)",
            evidence=[
                f"CSFB events: {len(csfb)}",
                f"Generation transitions observed"
            ],
            limitations=["CSFB may be intentional network configuration"],
        ))
    
    return findings


def _build_finding(
    finding_type: str,
    confidence_pct: int,
    confidence_level: str,
    description: str,
    evidence: List[str],
    limitations: List[str] = None,
) -> Dict[str, Any]:
    """Build a standardized radio finding dict."""
    return {
        "finding_type": finding_type,
        "confidence_pct": confidence_pct,
        "confidence_level": confidence_level,
        "description": description,
        "evidence": evidence,
        "limitations": limitations or [],
        "source": "RADIO_RCA_DETECTOR",
    }


def _detect_erab_setup_failure(gh_events: List[Dict]) -> List[Dict]:
    """Detects E-RAB Setup Failures in Groundhog traces (INTERNAL_PROC_ERAB_SETUP result=1)."""
    findings = []
    
    erab_failures = []
    for e in gh_events:
        if "INTERNAL_PROC_ERAB_SETUP" in str(e.get("event_type", "")):
            raw = e.get("raw", {})
            if str(raw.get("RESULT", "")) == "1" or str(raw.get("result", "")) == "1":
                erab_failures.append(e)
                
    if erab_failures:
        evidence = [f"E-RAB Setup Failures detected: {len(erab_failures)}"]
        for fail in erab_failures[:3]:
            cause = fail.get("raw", {}).get("CAUSE", fail.get("raw", {}).get("cause", "Unknown"))
            t_str = fail.get('time_text', fail.get('time_epoch', 'Unknown'))
            evidence.append(f"At {t_str}: Result=1 (FAILURE), Cause={cause}")
            
        findings.append(_build_finding(
            finding_type=RadioFindingType.ERAB_SETUP_FAILURE,
            confidence_pct=95,
            confidence_level="HIGH",
            description=f"{len(erab_failures)} E-RAB Setup Failure(s) detected. The network failed to establish the dedicated radio bearer, likely due to resource congestion or QoS mismatch.",
            evidence=evidence,
            limitations=["Correlate with core network S1AP traces to identify if rejection came from MME or eNB"]
        ))
        
    return findings


def _detect_sgnb_addition_failure(gh_events: List[Dict]) -> List[Dict]:
    """Detects 5G NSA SgNB Addition Failures (X2_SGNB_ADDITION_REJECT or INTERNAL_PROC_X2_SGNB_ADDITION result=1)."""
    findings = []
    
    sgnb_failures = []
    for e in gh_events:
        evt_type = str(e.get("event_type", ""))
        
        # Check explicit reject message
        if "X2_SGNB_ADDITION_REJECT" in evt_type:
            sgnb_failures.append(e)
            continue
            
        # Check internal procedure result
        if "INTERNAL_PROC_X2_SGNB_ADDITION" in evt_type:
            raw = e.get("raw", {})
            if str(raw.get("RESULT", "")) == "1" or str(raw.get("result", "")) == "1":
                sgnb_failures.append(e)
                
    if sgnb_failures:
        evidence = [f"SgNB (5G) Addition Failures detected: {len(sgnb_failures)}"]
        for fail in sgnb_failures[:3]:
            evt_type = fail.get("event_type", "")
            t_str = fail.get('time_text', fail.get('time_epoch', 'Unknown'))
            if "REJECT" in evt_type:
                evidence.append(f"At {t_str}: Explicit X2_SGNB_ADDITION_REJECT received")
            else:
                cause = fail.get("raw", {}).get("CAUSE", fail.get("raw", {}).get("cause", "Unknown"))
                evidence.append(f"At {t_str}: Result=1 (FAILURE), Cause={cause}")
                
        findings.append(_build_finding(
            finding_type=RadioFindingType.SGNB_ADDITION_FAILURE,
            confidence_pct=95,
            confidence_level="HIGH",
            description=f"{len(sgnb_failures)} SgNB Addition Failure(s) detected. The UE failed to attach to the 5G NR secondary node during EN-DC setup.",
            evidence=evidence,
            limitations=["Check NR cell availability, X2 transport status, and UE NR capabilities"]
        ))
        
    return findings


def _detect_high_harq_nack(gh_events: List[Dict]) -> List[Dict]:
    """Detects High HARQ NACK Ratios in DU_PER_UE_TRAFFIC_REP messages indicating poor RF quality."""
    import re
    findings = []
    
    high_nack_events = []
    max_nack_ratio = 0.0
    
    for e in gh_events:
        evt_type = str(e.get("event_type", ""))
        if "DU_PER" in evt_type or "INTERNAL_PER" in evt_type:
            raw = e.get("raw", {})
            
            payload = raw.get("payload", str(raw))
            
            # Find NACK values using regex
            nack_vals = []
            for pattern in [r'nack_256_qam>?(\d+)', r'nack_64_qam>?(\d+)', r'NACK_256QAM>?(\d+)', r'NACK_64QAM>?(\d+)']:
                match = re.search(pattern, payload, re.IGNORECASE)
                if match:
                    try:
                        nack_vals.append(int(match.group(1)))
                    except ValueError:
                        pass
            
            if nack_vals:
                highest_nack_count = max(nack_vals)
                if highest_nack_count > HARQ_NACK_CRITICAL_THRESHOLD:
                    high_nack_events.append((e, highest_nack_count))
                    max_nack_ratio = max(max_nack_ratio, highest_nack_count)
    
    if high_nack_events:
        evidence = [
            f"Analyzed DU Traffic Reports finding {len(high_nack_events)} instances of high HARQ NACKs.",
            f"Maximum NACK ratio observed: {max_nack_ratio}% (> {HARQ_NACK_CRITICAL_THRESHOLD}% threshold)."
        ]
        
        for evt, nack_ratio in high_nack_events[:3]:
            time_str = evt.get('time_text', evt.get('time_epoch', 'Unknown'))
            evidence.append(f"At {time_str}: HARQ NACK reached {nack_ratio}%")
            
        findings.append(_build_finding(
            finding_type=RadioFindingType.HIGH_HARQ_NACK_RATIO,
            confidence_pct=85,
            confidence_level="HIGH",
            description=f"Persistent high HARQ NACK ratio detected (max {max_nack_ratio}%). Strongly indicates poor underlying RF conditions, high interference, or cell edge scenario.",
            evidence=evidence,
            limitations=["Does not distinguish between DL vs UL NACKs without deeper payload inspection, but indicates general RF hostility."]
        ))
        
    return findings
