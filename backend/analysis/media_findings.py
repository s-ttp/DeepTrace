"""
Media Findings Module
Detects issues like One-Way Audio and Silent Calls based on RTP metrics.
"""
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class MediaFindings:
    def __init__(self):
        pass

    def analyze_streams(self, streams: List[Dict[str, Any]], calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate findings from media streams.
        """
        findings = []
        
        # Group streams by Call ID
        call_streams = {}
        for s in streams:
            cid = s["call_id"]
            if cid not in call_streams:
                call_streams[cid] = []
            call_streams[cid].append(s)
            
        for cid, streams in call_streams.items():
            # Find associated call
            call = next((c for c in calls if c["call_id"] == cid), None)
            if not call or call["state"] not in ["ESTABLISHED", "TERMINATED"]:
                continue # Only check calls that reached established state
            
            # Check 1: One-Way Audio
            # Expect at least one stream in each 'heuristic' direction or just count active streams
            # Simplified: If we have SDP, we likely expect streams for each listed media.
            # But let's check packet counts.
            
            low_pkt_streams = [s for s in streams if s["packets"] < 10]
            good_streams = [s for s in streams if s["packets"] >= 10]
            
            # If we have streams but only in one direction?
            # Directions are "Network->UE" or "UE->Network"
            directions = set(s["direction"] for s in good_streams)
            
            if len(good_streams) > 0 and len(directions) < 2:
                # Potential One-Way Audio
                # But assume simple case: A->B and B->A.
                # If we only see A->B, it's one-way.
                
                findings.append({
                    "call_id": cid,
                    "severity": "critical",
                    "title": "One-Way Audio Detected",
                    "description": f"RTP detected only in direction: {list(directions)[0]}",
                    "evidence": {
                        "call_id": cid,
                        "streams_found": len(good_streams),
                        "missing_direction": "Reverse path missing"
                    },
                    "confidence": "high"
                })
                
            # Check 2: Silent Call (RTP present but very low rate or empty)
            # If total packets are very low for call duration
            for s in good_streams:
                # If duration > 5s but packets < 50 => <10pps => likely silence or CNG only
                if s["duration_sec"] > 5 and (s["packets"] / s["duration_sec"]) < 10:
                     findings.append({
                        "call_id": cid,
                        "severity": "warning",
                        "title": "Silent Call / Low Activity",
                        "description": f"RTP packet rate very low ({round(s['packets']/s['duration_sec'],1)} pps)",
                        "evidence": stream_summary(s),
                        "confidence": "medium"
                    })
        
        return findings

def stream_summary(s):
    return f"{s['src_ip']}:{s['src_port']} -> {s['dst_ip']}:{s['dst_port']} ({s['packets']} pkts)"
