"""
Ringback Analyzer Module
Diagnoses missing ringback tone (no alerting indication to caller).
"""
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class RingbackAnalyzer:
    """
    Analyzes SIP call setup for ringback tone issues.
    
    Ringback tone scenarios:
    1. Local Ringback: UA generates tone locally (180 without SDP)
    2. Early Media Ringback: Network sends RTP/media tones (183 with SDP)
    3. P-Early-Media controlled: IMS policy controls early media direction
    """
    
    def __init__(self):
        pass
    
    def analyze_call_ringback(
        self, 
        call: Dict[str, Any],
        call_transactions: List[Dict[str, Any]],
        rtp_before_answer: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze ringback status for a single call.
        
        Args:
            call: Call object from CallBuilder
            call_transactions: SIP transactions for this call
            rtp_before_answer: Whether RTP was observed before 200 OK
            
        Returns:
            {
                "ringback_expected": bool,
                "ringback_type": "LOCAL" | "EARLY_MEDIA" | "NONE",
                "issue_detected": bool,
                "diagnosis": str,
                "evidence": {...}
            }
        """
        result = {
            "ringback_expected": True,
            "ringback_type": "NONE",
            "issue_detected": False,
            "diagnosis": None,
            "evidence": {}
        }
        
        # Track key events
        has_180 = False
        has_183 = False
        has_sdp_in_provisional = False
        sdp_direction = None
        p_early_media = None
        alert_info = None
        invite_time = None
        first_provisional_time = None
        ok_time = None
        
        for tx in call_transactions:
            msg_type = str(tx.get("message_type", "") or tx.get("type", ""))
            code = str(tx.get("cause", "") or tx.get("code", ""))
            timestamp = tx.get("timestamp", 0)
            
            # Track timing
            if msg_type == "INVITE" and invite_time is None:
                invite_time = timestamp
            
            # 180 Ringing
            if code == "180":
                has_180 = True
                if first_provisional_time is None:
                    first_provisional_time = timestamp
                
                # Check for SDP in 180
                sdp = tx.get("info", {}).get("sip.msg_body") or tx.get("sdp_raw")
                if sdp and ("m=audio" in sdp or "m=video" in sdp):
                    has_sdp_in_provisional = True
                    # Check direction
                    if "a=sendonly" in sdp:
                        sdp_direction = "sendonly"
                    elif "a=recvonly" in sdp:
                        sdp_direction = "recvonly"
                    elif "a=inactive" in sdp:
                        sdp_direction = "inactive"
                    else:
                        sdp_direction = "sendrecv"
            
            # 183 Session Progress
            if code == "183":
                has_183 = True
                if first_provisional_time is None:
                    first_provisional_time = timestamp
                
                # Check for SDP in 183
                sdp = tx.get("info", {}).get("sip.msg_body") or tx.get("sdp_raw")
                if sdp and ("m=audio" in sdp or "m=video" in sdp):
                    has_sdp_in_provisional = True
                    if "a=sendonly" in sdp:
                        sdp_direction = "sendonly"
                    elif "a=recvonly" in sdp:
                        sdp_direction = "recvonly"
                    elif "a=inactive" in sdp:
                        sdp_direction = "inactive"
                    else:
                        sdp_direction = "sendrecv"
            
            # P-Early-Media header
            pem = tx.get("info", {}).get("sip.P-Early-Media")
            if pem:
                p_early_media = pem.lower()
            
            # Alert-Info header
            ai = tx.get("info", {}).get("sip.Alert-Info")
            if ai:
                alert_info = ai
            
            # 200 OK
            if code == "200" and ok_time is None:
                ok_time = timestamp
        
        # Analyze ringback status
        result["evidence"] = {
            "has_180": has_180,
            "has_183": has_183,
            "has_sdp_in_provisional": has_sdp_in_provisional,
            "sdp_direction": sdp_direction,
            "p_early_media": p_early_media,
            "rtp_before_answer": rtp_before_answer
        }
        
        # Scenario 1: No provisional response at all
        if not has_180 and not has_183:
            result["ringback_type"] = "NONE"
            result["issue_detected"] = True
            result["diagnosis"] = "NO_PROVISIONAL_RESPONSE"
            result["evidence"]["detail"] = "No 180/183 response received - callee may not be alerting"
            return result
        
        # Scenario 2: 180 without SDP - Local ringback expected
        if has_180 and not has_sdp_in_provisional:
            result["ringback_type"] = "LOCAL"
            result["issue_detected"] = False
            result["diagnosis"] = "LOCAL_RINGBACK_EXPECTED"
            result["evidence"]["detail"] = "180 Ringing without SDP - caller UA should play local ringback"
            return result
        
        # Scenario 3: 183 with SDP - Early media
        if has_183 and has_sdp_in_provisional:
            result["ringback_type"] = "EARLY_MEDIA"
            
            # Check P-Early-Media restrictions
            if p_early_media == "inactive":
                result["issue_detected"] = True
                result["diagnosis"] = "EARLY_MEDIA_BLOCKED_BY_POLICY"
                result["evidence"]["detail"] = "P-Early-Media: inactive - IMS policy blocks early media"
                return result
            
            # Check SDP direction
            if sdp_direction == "inactive":
                result["issue_detected"] = True
                result["diagnosis"] = "EARLY_MEDIA_INACTIVE"
                result["evidence"]["detail"] = "SDP direction is inactive - no media in either direction"
                return result
            
            if sdp_direction == "recvonly":
                result["issue_detected"] = True
                result["diagnosis"] = "EARLY_MEDIA_WRONG_DIRECTION"
                result["evidence"]["detail"] = "SDP direction recvonly - caller cannot receive ringback"
                return result
            
            # Check if RTP was actually received
            if not rtp_before_answer and sdp_direction in ["sendrecv", "sendonly"]:
                result["issue_detected"] = True
                result["diagnosis"] = "EARLY_MEDIA_NOT_RECEIVED"
                result["evidence"]["detail"] = "Early media negotiated but no RTP observed before answer"
                return result
            
            # All good
            result["issue_detected"] = False
            result["diagnosis"] = "EARLY_MEDIA_OK"
            result["evidence"]["detail"] = "Early media setup correctly"
            return result
        
        # Scenario 4: 180 with SDP (less common)
        if has_180 and has_sdp_in_provisional:
            result["ringback_type"] = "EARLY_MEDIA"
            if not rtp_before_answer:
                result["issue_detected"] = True
                result["diagnosis"] = "EARLY_MEDIA_180_NO_RTP"
                result["evidence"]["detail"] = "180 with SDP but no early media RTP received"
            else:
                result["diagnosis"] = "EARLY_MEDIA_OK"
            return result
        
        return result
    
    def detect_ringback_issues(
        self, 
        calls: List[Dict[str, Any]], 
        transactions: List[Dict[str, Any]],
        media_presence: Dict[str, Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Detect ringback issues across all calls.
        
        Returns:
            List of ringback-related findings
        """
        findings = []
        
        # Group transactions by call_id
        call_txs = {}
        for tx in transactions:
            call_id = tx.get("session_ids", {}).get("call_id")
            if call_id:
                if call_id not in call_txs:
                    call_txs[call_id] = []
                call_txs[call_id].append(tx)
        
        for call in calls:
            call_id = call.get("call_id")
            if not call_id or call_id not in call_txs:
                continue
            
            # Skip if call never reached alerting (setup failure)
            if call.get("state") == "FAILED" and call.get("classification") in ["REJECTED_4XX", "REJECTED_5XX"]:
                continue
            
            # Determine if RTP was seen before answer
            rtp_before_answer = False
            if media_presence and call_id in media_presence:
                # If RTP was observed at all during call, assume some was before answer
                # (More precise would require timestamp correlation)
                presence = media_presence[call_id]
                rtp_before_answer = presence.get("rtp_presence") in ["BIDIRECTIONAL", "UNIDIRECTIONAL", "OBSERVED"]
            
            analysis = self.analyze_call_ringback(call, call_txs[call_id], rtp_before_answer)
            
            if analysis["issue_detected"]:
                severity = "warning"
                if analysis["diagnosis"] in ["NO_PROVISIONAL_RESPONSE", "EARLY_MEDIA_BLOCKED_BY_POLICY"]:
                    severity = "critical"
                
                findings.append({
                    "call_id": call_id,
                    "type": "ringback_issue",
                    "severity": severity,
                    "title": "No Ringback Tone",
                    "description": self._diagnosis_to_description(analysis["diagnosis"]),
                    "diagnosis_code": analysis["diagnosis"],
                    "evidence": analysis["evidence"],
                    "confidence": "high" if analysis["diagnosis"] in [
                        "NO_PROVISIONAL_RESPONSE", 
                        "EARLY_MEDIA_BLOCKED_BY_POLICY",
                        "EARLY_MEDIA_INACTIVE"
                    ] else "medium"
                })
        
        return findings
    
    def _diagnosis_to_description(self, diagnosis: str) -> str:
        """Convert diagnosis code to human-readable description."""
        descriptions = {
            "NO_PROVISIONAL_RESPONSE": "No 180/183 response received from callee - no alerting indication",
            "EARLY_MEDIA_BLOCKED_BY_POLICY": "P-Early-Media header set to 'inactive' - IMS policy prevents ringback",
            "EARLY_MEDIA_INACTIVE": "SDP direction 'inactive' in provisional - no media in either direction",
            "EARLY_MEDIA_WRONG_DIRECTION": "SDP direction prevents caller from receiving ringback audio",
            "EARLY_MEDIA_NOT_RECEIVED": "Early media negotiated in 183 but no RTP packets observed",
            "EARLY_MEDIA_180_NO_RTP": "180 Ringing included SDP for early media but RTP not received",
            "LOCAL_RINGBACK_EXPECTED": "180 without SDP - caller device should generate local ringback",
            "EARLY_MEDIA_OK": "Early media setup correctly"
        }
        return descriptions.get(diagnosis, diagnosis)


def format_ringback_context_for_llm(findings: List[Dict[str, Any]]) -> str:
    """Format ringback analysis for LLM prompt."""
    if not findings:
        return "## RINGBACK DIAGNOSIS: No ringback issues detected."
    
    lines = ["## RINGBACK DIAGNOSIS"]
    for f in findings[:5]:
        lines.append(f"- **{f['title']}** (Call: {f['call_id'][:8]}...)")
        lines.append(f"  - Diagnosis: {f['diagnosis_code']}")
        lines.append(f"  - {f['description']}")
        if f.get("evidence", {}).get("detail"):
            lines.append(f"  - Detail: {f['evidence']['detail']}")
    
    return "\n".join(lines)
