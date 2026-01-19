"""
Precondition Analyzer Module
Detects RFC 3312 QoS precondition failures in SIP/SDP negotiation.
"""
from typing import List, Dict, Any, Optional
import re
import logging

logger = logging.getLogger(__name__)


class PreconditionAnalyzer:
    """
    Analyzes SDP precondition attributes (a=curr, a=des, a=conf) for QoS reservation failures.
    
    RFC 3312 defines preconditions for SIP sessions:
    - a=des: Desired QoS level (mandatory/optional, sendrecv/send/recv/none)
    - a=curr: Current QoS level (achieved reservation status)
    - a=conf: Confirmed QoS level (acknowledgment)
    """
    
    def __init__(self):
        # Regex patterns for RFC 3312 precondition lines
        self.re_des = re.compile(r"a=des:qos\s+(\w+)\s+(\w+)\s+(\w+)")  # a=des:qos mandatory sendrecv
        self.re_curr = re.compile(r"a=curr:qos\s+(\w+)\s+(\w+)")  # a=curr:qos local none
        self.re_conf = re.compile(r"a=conf:qos\s+(\w+)\s+(\w+)")  # a=conf:qos remote sendrecv
    
    def parse_preconditions(self, sdp_text: str) -> Dict[str, Any]:
        """
        Extract precondition attributes from SDP.
        
        Returns:
            {
                "desired": [{"strength": "mandatory", "status_type": "e2e", "direction": "sendrecv"}],
                "current": [{"type": "local", "status": "none"}],
                "confirmed": [{"type": "remote", "status": "sendrecv"}],
                "has_preconditions": bool
            }
        """
        result = {
            "desired": [],
            "current": [],
            "confirmed": [],
            "has_preconditions": False
        }
        
        if not sdp_text:
            return result
        
        for line in sdp_text.splitlines():
            line = line.strip().lower()
            
            # Parse desired preconditions
            m_des = self.re_des.search(line)
            if m_des:
                result["desired"].append({
                    "strength": m_des.group(1),  # mandatory/optional
                    "status_type": m_des.group(2),  # local/remote/e2e
                    "direction": m_des.group(3)  # sendrecv/send/recv/none
                })
                result["has_preconditions"] = True
            
            # Parse current preconditions
            m_curr = self.re_curr.search(line)
            if m_curr:
                result["current"].append({
                    "type": m_curr.group(1),  # local/remote
                    "status": m_curr.group(2)  # sendrecv/send/recv/none
                })
                result["has_preconditions"] = True
            
            # Parse confirmed preconditions
            m_conf = self.re_conf.search(line)
            if m_conf:
                result["confirmed"].append({
                    "type": m_conf.group(1),
                    "status": m_conf.group(2)
                })
                result["has_preconditions"] = True
        
        return result
    
    def analyze_precondition_flow(
        self, 
        call_messages: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze precondition state across a call's SIP messages.
        
        Args:
            call_messages: List of SIP transactions for a single call
            
        Returns:
            {
                "preconditions_used": bool,
                "precondition_met": bool,
                "failure_type": str or None,
                "evidence": {...}
            }
        """
        result = {
            "preconditions_used": False,
            "precondition_met": None,
            "failure_type": None,
            "evidence": {}
        }
        
        precondition_states = []
        has_580 = False
        has_update_prack = False
        
        for msg in call_messages:
            msg_type = msg.get("type", "") or msg.get("message_type", "")
            sdp_body = msg.get("sdp_raw") or msg.get("info", {}).get("sip.msg_body", "")
            code = str(msg.get("code", "") or msg.get("cause", ""))
            
            # Check for 580 Precondition Failure
            if code == "580":
                has_580 = True
            
            # Check for UPDATE/PRACK (precondition updates)
            if msg_type in ["UPDATE", "PRACK"]:
                has_update_prack = True
            
            # Parse SDP for preconditions
            if sdp_body:
                preconditions = self.parse_preconditions(sdp_body)
                if preconditions["has_preconditions"]:
                    result["preconditions_used"] = True
                    precondition_states.append({
                        "msg_type": msg_type,
                        "preconditions": preconditions
                    })
        
        if not result["preconditions_used"]:
            return result
        
        # Analyze precondition outcome
        if has_580:
            result["precondition_met"] = False
            result["failure_type"] = "580_PRECONDITION_FAILURE"
            result["evidence"]["sip_response"] = "580 Precondition Failure"
        elif precondition_states:
            # Check if final state shows met preconditions
            last_state = precondition_states[-1]["preconditions"]
            
            # Check if all mandatory preconditions are met
            mandatory_met = True
            for des in last_state.get("desired", []):
                if des["strength"] == "mandatory":
                    # Look for matching current/confirmed
                    direction = des["direction"]
                    current_matched = any(
                        c["status"] == direction or c["status"] == "sendrecv"
                        for c in last_state.get("current", [])
                    )
                    confirmed_matched = any(
                        c["status"] == direction or c["status"] == "sendrecv"
                        for c in last_state.get("confirmed", [])
                    )
                    if not (current_matched or confirmed_matched):
                        mandatory_met = False
            
            result["precondition_met"] = mandatory_met
            if not mandatory_met:
                result["failure_type"] = "PRECONDITION_NOT_MET"
                result["evidence"]["final_state"] = last_state
        
        return result
    
    def detect_precondition_issues(
        self, 
        calls: List[Dict[str, Any]], 
        transactions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect precondition-related issues across all calls.
        
        Returns:
            List of precondition findings
        """
        findings = []
        
        # Group transactions by call_id
        call_transactions = {}
        for tx in transactions:
            call_id = tx.get("session_ids", {}).get("call_id")
            if call_id:
                if call_id not in call_transactions:
                    call_transactions[call_id] = []
                call_transactions[call_id].append(tx)
        
        for call in calls:
            call_id = call.get("call_id")
            if not call_id or call_id not in call_transactions:
                continue
            
            msgs = call_transactions[call_id]
            analysis = self.analyze_precondition_flow(msgs)
            
            if analysis["preconditions_used"] and not analysis["precondition_met"]:
                findings.append({
                    "call_id": call_id,
                    "type": "precondition_failure",
                    "severity": "critical",
                    "title": "QoS Precondition Failure",
                    "description": f"Call failed due to: {analysis['failure_type']}",
                    "evidence": analysis["evidence"],
                    "confidence": "high" if analysis["failure_type"] == "580_PRECONDITION_FAILURE" else "medium"
                })
        
        return findings


def format_precondition_context_for_llm(findings: List[Dict[str, Any]]) -> str:
    """Format precondition analysis for LLM prompt."""
    if not findings:
        return "## PRECONDITION STATUS: No QoS precondition issues detected."
    
    lines = ["## PRECONDITION STATUS (RFC 3312)"]
    for f in findings[:5]:
        lines.append(f"- **{f['title']}**: {f['description']}")
        if f.get("evidence"):
            lines.append(f"  - Evidence: {f['evidence']}")
    
    return "\n".join(lines)
