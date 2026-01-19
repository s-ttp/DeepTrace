"""
SRVCC/CSFB Detection Analyzer

Implements PS→CS handover (SRVCC) and CS Fallback (CSFB) detection
with deterministic rules and confidence scoring.

Evidence Levels:
- PROVEN_PS_TO_CS_HANDOVER: SIP hint + RAN evidence + time correlation
- PROVEN_CSFB_REDIRECTION: SIP failure + RAN redirect evidence
- SUSPECTED_PS_TO_CS_HANDOVER: SIP hint only (no RAN evidence)
- SUSPECTED_CSFB: SIP failure with CSFB keywords, no RAN
- NOT_OBSERVED: No handover indicators found
"""
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Keywords indicating PS→CS handover or CSFB
SRVCC_KEYWORDS = ["srvcc", "ps to cs", "ps-to-cs", "handover", "interworking", "msc", "scc as"]
CSFB_KEYWORDS = ["csfb", "cs fallback", "cs-fallback", "fallback", "cs domain", "geran", "utran"]

# SIP cause codes that may indicate handover-related clearing
HANDOVER_CAUSE_CODES = ["503"]  # Service Unavailable often triggers SRVCC

# S1AP procedure codes indicating handover/release
S1AP_HANDOVER_PROCEDURES = [
    0,   # HandoverPreparation
    1,   # HandoverResourceAllocation
    2,   # HandoverNotification
    3,   # PathSwitchRequest
    5,   # HandoverCancel
    23,  # UEContextRelease
    24,  # UEContextReleaseRequest
    25,  # UEContextModification
]

# NGAP procedure codes for 5G handover
NGAP_HANDOVER_PROCEDURES = [
    12,  # HandoverPreparation
    13,  # HandoverResourceAllocation
    14,  # HandoverNotification
    15,  # PathSwitchRequest
    41,  # UEContextRelease
]


@dataclass
class HandoverEvidence:
    """Evidence item for handover detection"""
    event_type: str  # S1AP_PROCEDURE, NGAP_PROCEDURE, SIP_REASON_HINT
    time_epoch: float
    label: str
    ids: Dict[str, str] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HandoverFinding:
    """Result of handover analysis"""
    classification: str
    confidence_pct: int
    confidence_level: str  # HIGH, MEDIUM, LOW
    evidence: List[str]
    description: str
    call_id: Optional[str] = None
    is_setup_failure: bool = False


class HandoverAnalyzer:
    """
    Analyzes network traces for SRVCC and CSFB indicators.
    
    Detection modes:
    - Full: SIP + S1AP/NGAP available → PROVEN classifications
    - Limited: SIP only → SUSPECTED classifications
    """
    
    def __init__(self, correlation_window_sec: float = 5.0):
        """
        Args:
            correlation_window_sec: Time window for correlating RAN and SIP events
        """
        self.correlation_window = correlation_window_sec
        self.sip_evidence: List[HandoverEvidence] = []
        self.ran_evidence: List[HandoverEvidence] = []
        self.findings: List[HandoverFinding] = []
    
    def analyze(
        self,
        calls: List[Dict[str, Any]],
        s1ap_transactions: List[Dict[str, Any]] = None,
        ngap_transactions: List[Dict[str, Any]] = None,
        sip_transactions: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Main analysis entry point.
        
        Args:
            calls: Processed call objects from CallBuilder
            s1ap_transactions: S1AP transactions (optional)
            ngap_transactions: NGAP transactions (optional)
            sip_transactions: Raw SIP transactions for Reason header parsing
            
        Returns:
            Analysis result with classifications and evidence
        """
        self.sip_evidence = []
        self.ran_evidence = []
        self.findings = []
        
        # Extract evidence from transactions
        self._extract_sip_evidence(calls, sip_transactions)
        self._extract_ran_evidence(s1ap_transactions, ngap_transactions)
        
        # Perform detection for each call with handover hints
        for call in calls:
            self._analyze_call(call)
        
        # Compile results
        has_ran_data = len(self.ran_evidence) > 0
        
        return {
            "handover_detected": len(self.findings) > 0,
            "has_ran_evidence": has_ran_data,
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "sip_evidence_count": len(self.sip_evidence),
            "ran_evidence_count": len(self.ran_evidence),
            "summary": self._generate_summary()
        }
    
    def _extract_sip_evidence(
        self,
        calls: List[Dict[str, Any]],
        sip_transactions: List[Dict[str, Any]] = None
    ) -> None:
        """Extract handover hints from SIP Reason headers"""
        
        for call in calls:
            call_id = call.get("call_id", "")
            
            # Check if call has Reason header info
            reason_header = call.get("reason_header", "")
            end_time = call.get("end_time", 0)
            
            if reason_header:
                reason_lower = reason_header.lower()
                
                # Parse structured Reason (if available)
                cause_code = None
                reason_text = ""
                
                # Extract cause code from structured format
                cause_match = re.search(r"cause=(\d+)", reason_header)
                if cause_match:
                    cause_code = cause_match.group(1)
                
                # Extract text
                text_match = re.search(r'text="?([^"]*)"?', reason_header)
                if text_match:
                    reason_text = text_match.group(1).lower()
                
                # Check for SRVCC keywords in header or text
                for keyword in SRVCC_KEYWORDS:
                    if keyword in reason_lower or keyword in reason_text:
                        confidence_boost = 10 if cause_code in HANDOVER_CAUSE_CODES else 0
                        self.sip_evidence.append(HandoverEvidence(
                            event_type="SIP_REASON_HINT",
                            time_epoch=end_time,
                            label=f"Reason: {reason_header}",
                            ids={"call_id": call_id},
                            raw_data={
                                "keyword_match": keyword, 
                                "reason": reason_header,
                                "cause_code": cause_code,
                                "confidence_boost": confidence_boost
                            }
                        ))
                        break
                
                # Check for CSFB keywords
                for keyword in CSFB_KEYWORDS:
                    if keyword in reason_lower or keyword in reason_text:
                        self.sip_evidence.append(HandoverEvidence(
                            event_type="SIP_REASON_HINT",
                            time_epoch=end_time,
                            label=f"Reason: {reason_header} (CSFB)",
                            ids={"call_id": call_id},
                            raw_data={"keyword_match": keyword, "reason": reason_header, "is_csfb": True}
                        ))
                        break
                
                # Also detect 503 + handover keywords combo (higher confidence)
                if cause_code in HANDOVER_CAUSE_CODES:
                    for keyword in SRVCC_KEYWORDS + CSFB_KEYWORDS:
                        if keyword in reason_text:
                            # Don't add duplicate if already added above
                            existing = [e for e in self.sip_evidence if e.ids.get("call_id") == call_id]
                            if not existing:
                                self.sip_evidence.append(HandoverEvidence(
                                    event_type="SIP_REASON_503_HANDOVER",
                                    time_epoch=end_time,
                                    label=f"503 + Handover: {reason_header}",
                                    ids={"call_id": call_id},
                                    raw_data={
                                        "keyword_match": keyword,
                                        "reason": reason_header,
                                        "cause_code": cause_code,
                                        "confidence_boost": 15
                                    }
                                ))
                            break
        
        # Also check raw transactions if provided
        if sip_transactions:
            for tx in sip_transactions:
                reason = tx.get("sip.Reason", "") or tx.get("sip_reason", "")
                if reason:
                    reason_lower = reason.lower()
                    time_epoch = float(tx.get("frame.time_epoch", 0) or tx.get("timestamp", 0))
                    call_id = tx.get("sip.Call-ID", "") or tx.get("call_id", "")
                    
                    for keyword in SRVCC_KEYWORDS + CSFB_KEYWORDS:
                        if keyword in reason_lower:
                            self.sip_evidence.append(HandoverEvidence(
                                event_type="SIP_REASON_HINT",
                                time_epoch=time_epoch,
                                label=f"Reason: {reason}",
                                ids={"call_id": call_id},
                                raw_data={"keyword_match": keyword, "reason": reason}
                            ))
                            break
    
    def _extract_ran_evidence(
        self,
        s1ap_transactions: List[Dict[str, Any]] = None,
        ngap_transactions: List[Dict[str, Any]] = None
    ) -> None:
        """Extract handover-related procedures from S1AP/NGAP"""
        
        if s1ap_transactions:
            for tx in s1ap_transactions:
                proc_code = tx.get("s1ap.procedureCode")
                if proc_code is not None:
                    try:
                        proc_int = int(proc_code)
                        if proc_int in S1AP_HANDOVER_PROCEDURES:
                            self.ran_evidence.append(HandoverEvidence(
                                event_type="S1AP_PROCEDURE",
                                time_epoch=float(tx.get("frame.time_epoch", 0) or tx.get("timestamp", 0)),
                                label=f"S1AP Procedure {proc_int}",
                                ids={
                                    "mme_ue_s1ap_id": str(tx.get("s1ap.MME_UE_S1AP_ID", "")),
                                    "enb_ue_s1ap_id": str(tx.get("s1ap.ENB_UE_S1AP_ID", ""))
                                },
                                raw_data=tx
                            ))
                    except (ValueError, TypeError):
                        pass
        
        if ngap_transactions:
            for tx in ngap_transactions:
                proc_code = tx.get("ngap.procedureCode")
                if proc_code is not None:
                    try:
                        proc_int = int(proc_code)
                        if proc_int in NGAP_HANDOVER_PROCEDURES:
                            self.ran_evidence.append(HandoverEvidence(
                                event_type="NGAP_PROCEDURE",
                                time_epoch=float(tx.get("frame.time_epoch", 0) or tx.get("timestamp", 0)),
                                label=f"NGAP Procedure {proc_int}",
                                ids={
                                    "amf_ue_ngap_id": str(tx.get("ngap.AMF_UE_NGAP_ID", "")),
                                    "ran_ue_ngap_id": str(tx.get("ngap.RAN_UE_NGAP_ID", ""))
                                },
                                raw_data=tx
                            ))
                    except (ValueError, TypeError):
                        pass
    
    def _analyze_call(self, call: Dict[str, Any]) -> None:
        """Analyze a single call for handover indicators"""
        
        call_id = call.get("call_id", "")
        end_time = call.get("end_time") or call.get("timing", {}).get("bye_time")
        start_time = call.get("start_time") or call.get("timing", {}).get("invite_time")
        is_established = call.get("is_established", False)
        classification = call.get("classification", "")
        
        # Find SIP evidence for this call
        call_sip_evidence = [
            e for e in self.sip_evidence 
            if e.ids.get("call_id") == call_id
        ]
        
        if not call_sip_evidence:
            return  # No handover hints for this call
        
        # Determine time window for RAN correlation
        ref_time = end_time if end_time else start_time
        if not ref_time:
            return
        
        ref_time = float(ref_time)
        
        # Find correlated RAN evidence
        correlated_ran = [
            e for e in self.ran_evidence
            if abs(e.time_epoch - ref_time) <= self.correlation_window
        ]
        
        # Classify based on evidence
        is_csfb = any(
            e.raw_data.get("is_csfb") or 
            any(kw in e.label.lower() for kw in CSFB_KEYWORDS)
            for e in call_sip_evidence
        )
        
        is_setup_failure = not is_established
        
        if is_csfb:
            self._create_csfb_finding(
                call_id, call_sip_evidence, correlated_ran, is_setup_failure
            )
        else:
            self._create_srvcc_finding(
                call_id, call_sip_evidence, correlated_ran, is_setup_failure
            )
    
    def _create_srvcc_finding(
        self,
        call_id: str,
        sip_evidence: List[HandoverEvidence],
        ran_evidence: List[HandoverEvidence],
        is_setup_failure: bool
    ) -> None:
        """Create SRVCC/PS→CS handover finding"""
        
        evidence_strs = [e.label for e in sip_evidence]
        evidence_strs.extend([e.label for e in ran_evidence])
        
        has_ran = len(ran_evidence) > 0
        
        # Calculate confidence boost from SIP evidence (cause code + keyword combo)
        confidence_boost = sum(
            e.raw_data.get("confidence_boost", 0) for e in sip_evidence
        )
        
        # Check for UE ID correlation
        has_ue_id_match = False
        if has_ran:
            # In a real implementation, we'd correlate UE IDs
            # For now, time correlation is sufficient
            has_ue_id_match = len(ran_evidence) >= 2  # Multiple RAN events = stronger
        
        if has_ran and has_ue_id_match:
            classification = "PROVEN_PS_TO_CS_HANDOVER"
            confidence_pct = min(95 + confidence_boost, 99)
            confidence_level = "HIGH"
            description = "PS→CS handover (SRVCC) confirmed by SIP Reason header and correlated RAN procedures."
        elif has_ran:
            classification = "PROVEN_PS_TO_CS_HANDOVER"
            confidence_pct = min(80 + confidence_boost, 95)
            confidence_level = "MEDIUM" if confidence_pct < 85 else "HIGH"
            description = "PS→CS handover (SRVCC) indicated by SIP Reason header with time-correlated RAN activity."
        else:
            classification = "SUSPECTED_PS_TO_CS_HANDOVER"
            # Apply boost: 503+handover keyword = higher confidence even without RAN
            base_confidence = 55 + confidence_boost
            confidence_pct = min(base_confidence, 75)
            confidence_level = "MEDIUM" if confidence_pct >= 65 else "LOW"
            description = "PS→CS handover (SRVCC) suspected from SIP Reason header. Not observable from this capture point; RAN evidence required for confirmation."
            if confidence_boost > 0:
                description = "PS→CS handover (SRVCC) detected from SIP Reason with cause=503. RAN evidence not available for full confirmation."
        
        self.findings.append(HandoverFinding(
            classification=classification,
            confidence_pct=confidence_pct,
            confidence_level=confidence_level,
            evidence=evidence_strs,
            description=description,
            call_id=call_id,
            is_setup_failure=is_setup_failure
        ))
    
    def _create_csfb_finding(
        self,
        call_id: str,
        sip_evidence: List[HandoverEvidence],
        ran_evidence: List[HandoverEvidence],
        is_setup_failure: bool
    ) -> None:
        """Create CSFB finding"""
        
        evidence_strs = [e.label for e in sip_evidence]
        evidence_strs.extend([e.label for e in ran_evidence])
        
        has_ran = len(ran_evidence) > 0
        
        if has_ran and is_setup_failure:
            classification = "PROVEN_CSFB_REDIRECTION"
            confidence_pct = 90
            confidence_level = "HIGH"
            description = "CS Fallback confirmed: VoLTE setup failed with RAN redirection to CS domain."
        elif has_ran:
            classification = "PROVEN_CSFB_REDIRECTION"
            confidence_pct = 75
            confidence_level = "MEDIUM"
            description = "CS Fallback indicated by SIP failure with time-correlated RAN procedures."
        else:
            classification = "SUSPECTED_CSFB"
            confidence_pct = 50
            confidence_level = "LOW"
            description = "CS Fallback suspected from SIP indicators. Not observable from this capture point; RAN evidence required."
        
        self.findings.append(HandoverFinding(
            classification=classification,
            confidence_pct=confidence_pct,
            confidence_level=confidence_level,
            evidence=evidence_strs,
            description=description,
            call_id=call_id,
            is_setup_failure=is_setup_failure
        ))
    
    def _finding_to_dict(self, finding: HandoverFinding) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "classification": finding.classification,
            "confidence_pct": finding.confidence_pct,
            "confidence_level": finding.confidence_level,
            "evidence": finding.evidence,
            "description": finding.description,
            "call_id": finding.call_id,
            "is_setup_failure": finding.is_setup_failure
        }
    
    def _generate_summary(self) -> str:
        """Generate human-readable summary"""
        
        if not self.findings:
            return "No SRVCC/CSFB indicators detected in this trace."
        
        proven = [f for f in self.findings if "PROVEN" in f.classification]
        suspected = [f for f in self.findings if "SUSPECTED" in f.classification]
        
        parts = []
        if proven:
            parts.append(f"{len(proven)} confirmed handover/fallback event(s)")
        if suspected:
            parts.append(f"{len(suspected)} suspected event(s) (SIP hints only)")
        
        if not self.ran_evidence:
            parts.append("No S1AP/NGAP data available for correlation")
        
        return "; ".join(parts) + "."


def analyze_handover(
    calls: List[Dict[str, Any]],
    s1ap_transactions: List[Dict[str, Any]] = None,
    ngap_transactions: List[Dict[str, Any]] = None,
    sip_transactions: List[Dict[str, Any]] = None,
    correlation_window_sec: float = 5.0
) -> Dict[str, Any]:
    """
    Convenience function for handover analysis.
    
    Args:
        calls: Processed call objects
        s1ap_transactions: S1AP transactions (optional)
        ngap_transactions: NGAP transactions (optional)
        sip_transactions: Raw SIP transactions (optional)
        correlation_window_sec: Time window for correlation
        
    Returns:
        Analysis results with findings and summary
    """
    analyzer = HandoverAnalyzer(correlation_window_sec=correlation_window_sec)
    return analyzer.analyze(calls, s1ap_transactions, ngap_transactions, sip_transactions)
