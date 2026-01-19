"""
Media Mapper Module
Correlates observed RTP streams with expected SDP media definitions.
"""
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class MediaMapper:
    def __init__(self):
        pass

    def map_streams_to_calls(self, 
                             calls: List[Dict[str, Any]], 
                             call_media: Dict[str, List[Dict[str, Any]]], 
                             flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
         Match flows to calls.
         Returns a list of enriched media streams.
        """
        mapped_streams = []
        
        # Index flows by src_ip:src_port and dst_ip:dst_port
        # Flows are usually unidirectional in NetTrace
        
        for cid, media_list in call_media.items():
            for m in media_list:
                expected_ip = m.get("ip")
                expected_port = m.get("port")
                
                if not expected_ip or not expected_port:
                    continue
                
                # Find flows matching this destination (RTP sent TO the SDP endpoint)
                matching_flows = [
                    f for f in flows 
                    if f.get("dst_ip") == expected_ip and f["dst_port"] == expected_port
                ]
                
                for f in matching_flows:
                    stream = {
                        "call_id": cid,
                        "type": "audio",
                        "codec": m.get("codec"),
                        "src_ip": f.get("src_ip"),
                        "src_port": f.get("src_port"),
                        "dst_ip": f.get("dst_ip"),
                        "dst_port": f.get("dst_port"),
                        "packets": f.get("packet_count", 0),
                        "bytes": f.get("total_bytes", 0),
                        "duration_sec": f.get("duration", 0),
                        "flow_key": f.get("flow_id"), # Link to flow
                        "direction": "Network->UE" if f.get("dst_ip") == expected_ip else "UE->Network" # Heuristic
                    }
                    mapped_streams.append(stream)
                    
        return mapped_streams
