"""
RTP Presence Detector Module
Matches SDP-advertised media ports with observed RTP/RTCP flows.
Generates coverage flags for accurate analysis.
"""
from typing import Dict, Any, List, Set

class RtpPresenceDetector:
    """
    Detects RTP presence by comparing SDP-advertised ports with observed traffic.
    """
    
    def __init__(self):
        pass
    
    def detect_presence(
        self, 
        call_media: Dict[str, Dict[str, Any]], 
        flows: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        For each call, determine RTP presence status.
        
        Args:
            call_media: Output from SdpParser.extract_from_transactions()
                        {call_id: {"offer": [...], "answer": [...], "expected_ports": [...]}}
            flows: List of flow dictionaries from flow analysis
        
        Returns:
            {call_id: {
                "sdp_present": bool,
                "expected_ports": list,
                "observed_ports": list,
                "rtp_presence": "BIDIRECTIONAL" | "UNIDIRECTIONAL" | "NOT_OBSERVED",
                "coverage_flag": str,
                "media_endpoints": [...]
            }}
        """
        # Extract all observed RTP-like ports from flows
        observed_rtp_ports = set()
        observed_rtp_flows = []
        
        for flow in flows:
            protocol = flow.get("protocol", "").upper()
            src_port = flow.get("src_port", 0)
            dst_port = flow.get("dst_port", 0)
            
            # RTP detection: protocol name or typical port range
            is_rtp = "RTP" in protocol or (
                16384 <= src_port <= 32767 or 16384 <= dst_port <= 32767
            )
            
            if is_rtp or protocol in ["RTP", "RTCP"]:
                observed_rtp_ports.add(src_port)
                observed_rtp_ports.add(dst_port)
                observed_rtp_flows.append({
                    "src": f"{flow.get('src_ip', '')}:{src_port}",
                    "dst": f"{flow.get('dst_ip', '')}:{dst_port}",
                    "packets": flow.get("packet_count", 0),
                    "direction": self._determine_direction(flow)
                })
        
        results = {}
        
        for call_id, media_info in call_media.items():
            expected_ports = set(media_info.get("expected_ports", []))
            sdp_present = len(media_info.get("offer", [])) > 0 or len(media_info.get("answer", [])) > 0
            
            # Find matches
            matched_ports = expected_ports & observed_rtp_ports
            
            # Determine presence status
            if not sdp_present:
                rtp_presence = "NO_SDP"
                coverage_flag = "SDP not present in capture - cannot determine expected media"
            elif not expected_ports:
                rtp_presence = "NO_EXPECTED_PORTS"
                coverage_flag = "SDP present but no media ports advertised (hold?)"
            elif len(matched_ports) == 0:
                rtp_presence = "NOT_OBSERVED"
                coverage_flag = "Media plane not captured at this observation point"
            else:
                # Check for bidirectional RTP
                directions = set()
                for rtp_flow in observed_rtp_flows:
                    if rtp_flow["src"].split(":")[1] in [str(p) for p in expected_ports] or \
                       rtp_flow["dst"].split(":")[1] in [str(p) for p in expected_ports]:
                        directions.add(rtp_flow["direction"])
                
                if len(directions) >= 2:
                    rtp_presence = "BIDIRECTIONAL"
                    coverage_flag = "Full media plane captured"
                elif len(directions) == 1:
                    rtp_presence = "UNIDIRECTIONAL"
                    coverage_flag = f"RTP only in {list(directions)[0]} direction - possible one-way audio"
                else:
                    rtp_presence = "OBSERVED"
                    coverage_flag = "RTP packets matched to SDP ports"
            
            results[call_id] = {
                "sdp_present": sdp_present,
                "expected_ports": list(expected_ports),
                "observed_ports": list(matched_ports),
                "rtp_presence": rtp_presence,
                "coverage_flag": coverage_flag,
                "media_endpoints": self._extract_endpoints(media_info)
            }
        
        return results
    
    def _determine_direction(self, flow: Dict[str, Any]) -> str:
        """Heuristically determine direction based on IP patterns."""
        src_ip = flow.get("src_ip", "")
        
        # Private IP ranges typically indicate network side
        if src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172."):
            return "network_to_ue"
        return "ue_to_network"
    
    def _extract_endpoints(self, media_info: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract media endpoints from offer/answer."""
        endpoints = []
        for phase in ["offer", "answer"]:
            for m in media_info.get(phase, []):
                if m.get("ip") and m.get("port"):
                    endpoints.append({
                        "phase": phase,
                        "type": m.get("type", "audio"),
                        "endpoint": f"{m['ip']}:{m['port']}",
                        "direction": m.get("direction", "sendrecv")
                    })
        return endpoints


def generate_coverage_summary(presence_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate aggregate coverage summary for all calls.
    """
    total_calls = len(presence_results)
    if total_calls == 0:
        return {
            "total_calls": 0,
            "media_captured": 0,
            "media_not_captured": 0,
            "bidirectional": 0,
            "unidirectional": 0,
            "coverage_rate": 0.0
        }
    
    bidirectional = sum(1 for r in presence_results.values() if r["rtp_presence"] == "BIDIRECTIONAL")
    unidirectional = sum(1 for r in presence_results.values() if r["rtp_presence"] == "UNIDIRECTIONAL")
    not_observed = sum(1 for r in presence_results.values() if r["rtp_presence"] == "NOT_OBSERVED")
    
    return {
        "total_calls": total_calls,
        "media_captured": bidirectional + unidirectional,
        "media_not_captured": not_observed,
        "bidirectional": bidirectional,
        "unidirectional": unidirectional,
        "coverage_rate": round((bidirectional + unidirectional) / total_calls * 100, 1) if total_calls > 0 else 0.0
    }
