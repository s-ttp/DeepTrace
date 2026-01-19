"""
SDP Parser Module
Extracts media details (IP, Port, Codec, Direction) from SIP SDP bodies.
Enhanced with:
- Offer/Answer tracking
- Expected RTP port extraction for presence detection
"""
import re
from typing import Dict, Any, List, Optional

class SdpParser:
    def __init__(self):
        # Basic Regex for SDP lines
        self.re_audio = re.compile(r"m=audio (\d+) (?:RTP/AVP|RTP/SAVP|UDP/TLS/RTP/SAVP) ([\d\s]+)")
        self.re_video = re.compile(r"m=video (\d+) (?:RTP/AVP|RTP/SAVP|UDP/TLS/RTP/SAVP) ([\d\s]+)")
        self.re_c = re.compile(r"c=IN IP[46] ([\d\.:a-fA-F]+)")
        self.re_dir = re.compile(r"a=(sendrecv|sendonly|recvonly|inactive)")
        self.re_rtpmap = re.compile(r"a=rtpmap:(\d+) ([^/]+)")

    def parse_sdp(self, sdp_text: str, phase: str = "unknown") -> List[Dict[str, Any]]:
        """
        Extract media definitions from raw SDP text.
        Args:
            sdp_text: Raw SDP content
            phase: "offer" or "answer" to track negotiation
        Returns a list of media descriptions.
        """
        media = []
        if not sdp_text:
            return media
            
        current_ip = None
        direction = "sendrecv" # Default
        codecs = {}  # PT -> codec name
        
        lines = sdp_text.splitlines()
        
        # First pass: collect rtpmap entries
        for line in lines:
            m_rtpmap = self.re_rtpmap.search(line)
            if m_rtpmap:
                codecs[m_rtpmap.group(1)] = m_rtpmap.group(2)
        
        # Second pass: extract media
        for line in lines:
            line = line.strip()
            
            # Connection IP
            m_c = self.re_c.search(line)
            if m_c:
                current_ip = m_c.group(1)
                
            # Direction Attribute
            m_dir = self.re_dir.search(line)
            if m_dir:
                direction = m_dir.group(1)
            
            # Audio Media Line
            m_audio = self.re_audio.search(line)
            if m_audio:
                port = int(m_audio.group(1))
                payload_types = m_audio.group(2).split()
                
                # Get codec name for first payload type
                first_pt = payload_types[0] if payload_types else "0"
                codec = codecs.get(first_pt, f"PT-{first_pt}")
                
                media.append({
                    "type": "audio",
                    "ip": current_ip,
                    "port": port,
                    "rtcp_port": port + 1,  # RTCP typically on port+1
                    "codec": codec,
                    "payload_types": payload_types,
                    "direction": direction,
                    "phase": phase
                })
            
            # Video Media Line
            m_video = self.re_video.search(line)
            if m_video:
                port = int(m_video.group(1))
                payload_types = m_video.group(2).split()
                first_pt = payload_types[0] if payload_types else "96"
                codec = codecs.get(first_pt, f"PT-{first_pt}")
                
                media.append({
                    "type": "video",
                    "ip": current_ip,
                    "port": port,
                    "rtcp_port": port + 1,
                    "codec": codec,
                    "payload_types": payload_types,
                    "direction": direction,
                    "phase": phase
                })
                
        return media

    def extract_from_transactions(self, transactions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Extract SDP info per Call-ID with offer/answer tracking.
        Returns: {call_id: {"offer": [...], "answer": [...], "expected_ports": [...]}}
        """
        call_media = {}
        
        for tx in transactions:
            call_id = tx.get("session_ids", {}).get("call_id")
            if not call_id:
                continue
            
            # Try multiple sources for SDP
            sdp = tx.get("info", {}).get("sdp_raw")
            if not sdp:
                sdp = tx.get("info", {}).get("sip.msg_body")
            
            if not sdp:
                continue
            
            # Determine phase based on message type
            msg_type = tx.get("message_type", "")
            if msg_type == "INVITE" or "183" in msg_type:
                phase = "offer"
            elif "200" in str(tx.get("cause", "")):
                phase = "answer"
            else:
                phase = "unknown"
            
            extracted = self.parse_sdp(sdp, phase)
            if extracted:
                if call_id not in call_media:
                    call_media[call_id] = {
                        "offer": [],
                        "answer": [],
                        "expected_ports": set()
                    }
                
                for m in extracted:
                    if phase == "offer":
                        call_media[call_id]["offer"].append(m)
                    elif phase == "answer":
                        call_media[call_id]["answer"].append(m)
                    
                    # Track expected RTP ports
                    if m.get("port") and m["port"] > 0:
                        call_media[call_id]["expected_ports"].add(m["port"])
                        if m.get("rtcp_port"):
                            call_media[call_id]["expected_ports"].add(m["rtcp_port"])
        
        # Convert sets to lists for JSON serialization
        for cid in call_media:
            call_media[cid]["expected_ports"] = list(call_media[cid]["expected_ports"])
        
        return call_media

