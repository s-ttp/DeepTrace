"""Telecom protocol analyzer - aggregates packets into flows
Supports 2G/3G/4G/5G mobile technologies"""
from collections import defaultdict
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


def analyze_flows(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Aggregate packets into flows based on 5-tuple
    Includes mobile technology classification
    
    Args:
        packets: List of parsed packet dictionaries
        
    Returns:
        List of flow dictionaries with aggregated statistics
    """
    logger.info(f"Analyzing {len(packets)} packets into flows")
    
    flows_dict = defaultdict(lambda: {
        "packet_count": 0,
        "total_bytes": 0,
        "timestamps": [],
        "protocols": set(),
        "technologies": set(),
        "tcp_flags": set(),
        "gtp_teids": set(),
        "diameter_apps": set(),
        "analysis_events": [],  # Store RCA events
    })
    
    for pkt in packets:
        # Skip packets without IP info
        if "src_ip" not in pkt or "dst_ip" not in pkt:
            continue
        
        # Create bidirectional flow key (sorted IPs for consistency)
        src = (pkt["src_ip"], pkt.get("src_port", 0))
        dst = (pkt["dst_ip"], pkt.get("dst_port", 0))
        
        # Normalize flow direction
        if src > dst:
            src, dst = dst, src
        
        flow_key = (
            src[0], dst[0],  # IPs
            src[1], dst[1],  # Ports
            pkt.get("transport", "Unknown")
        )
        
        flow = flows_dict[flow_key]
        flow["packet_count"] += 1
        flow["total_bytes"] += pkt.get("length", 0)
        flow["timestamps"].append(pkt["timestamp"])
        flow["protocols"].add(pkt.get("protocol", "Unknown"))
        
        # Track mobile technology
        if pkt.get("technology"):
            flow["technologies"].add(pkt["technology"])
        
        # Track TCP flags
        if "tcp_flags" in pkt:
            flow["tcp_flags"].add(pkt["tcp_flags"])
        
        # Track GTP TEIDs
        if "gtp" in pkt and pkt["gtp"].get("teid"):
            flow["gtp_teids"].add(pkt["gtp"]["teid"])
        
        # Track Diameter application IDs
        if "diameter" in pkt and pkt["diameter"].get("app_id"):
            flow["diameter_apps"].add(pkt["diameter"]["app_id"])
            
        # Collect Analysis Events (RCA)
        if "analysis_info" in pkt:
            flow["analysis_events"].append(pkt["analysis_info"])
        
        # Store flow identifiers (use original packet direction)
        if "src_ip" not in flow:
            flow["src_ip"] = pkt["src_ip"]
            flow["dst_ip"] = pkt["dst_ip"]
            flow["src_port"] = pkt.get("src_port", 0)
            flow["dst_port"] = pkt.get("dst_port", 0)
            flow["transport"] = pkt.get("transport", "Unknown")
    
    # Process and format flows
    flows = []
    for flow in flows_dict.values():
        if flow["timestamps"]:
            timestamps = flow["timestamps"]
            flow["duration"] = max(timestamps) - min(timestamps)
            flow["start_time"] = min(timestamps)
            flow["end_time"] = max(timestamps)
            
            # Calculate packets per second
            if flow["duration"] > 0:
                flow["pps"] = round(flow["packet_count"] / flow["duration"], 2)
            else:
                flow["pps"] = flow["packet_count"]
        
        # Convert sets to lists for JSON serialization
        flow["protocols"] = list(flow["protocols"])
        flow["protocol"] = "/".join(flow["protocols"]) if flow["protocols"] else "Unknown"
        
        # Mobile technology
        flow["technologies"] = list(flow["technologies"])
        flow["technology"] = "/".join(flow["technologies"]) if flow["technologies"] else "Unknown"
        
        if flow["tcp_flags"]:
            flow["tcp_flags"] = list(flow["tcp_flags"])
        else:
            del flow["tcp_flags"]
        
        if flow["gtp_teids"]:
            flow["gtp_teids"] = list(flow["gtp_teids"])
            flow["is_gtp"] = True
        else:
            del flow["gtp_teids"]
            flow["is_gtp"] = False
        
        if flow["diameter_apps"]:
            flow["diameter_apps"] = list(flow["diameter_apps"])
            flow["is_diameter"] = True
        else:
            del flow["diameter_apps"]
            flow["is_diameter"] = False
        
        # Determine primary technology for display
        flow["primary_tech"] = get_primary_technology(flow["technologies"])
        
        # Remove internal fields
        del flow["timestamps"]
        del flow["protocols"]  # Keep only the combined protocol string
        del flow["technologies"]  # Keep only the combined technology string
        
        # Summarize analysis events for the flow
        if flow["analysis_events"]:
            flow["failures"] = [e for e in flow["analysis_events"] if "failure_code" in e]
            flow["has_errors"] = len(flow["failures"]) > 0
            del flow["analysis_events"] # Clean up raw list
        
        flows.append(flow)
    
    # Sort by packet count (most active first)
    flows.sort(key=lambda x: x["packet_count"], reverse=True)
    
    logger.info(f"Identified {len(flows)} unique flows")
    return flows


def correlate_sessions(flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Advanced AI Enhancement: Correlate independent flows into high-level user sessions.
    Example: Link GTP-U (User Plane) with GTP-C (Control Plane) or SIP (Signaling).
    """
    correlated = []
    
    # 1. Group by GTP TEID (Core Mobile Correlation)
    teid_map = defaultdict(list)
    for f in flows:
        for teid in f.get("gtp_teids", []):
            teid_map[teid].append(f)
            
    # 2. Group by Common IP Pairs (Signaling + Data Correlation)
    ip_pair_map = defaultdict(list)
    for f in flows:
        pair = tuple(sorted([f["src_ip"], f["dst_ip"]]))
        ip_pair_map[pair].append(f)
        
    # Create high-level session objects for the AI to analyze
    for pair, session_flows in ip_pair_map.items():
        if len(session_flows) > 1:
            protocols = set(f["protocol"] for f in session_flows)
            technologies = set(f["primary_tech"] for f in session_flows)
            
            correlated.append({
                "endpoints": pair,
                "flow_count": len(session_flows),
                "protocols": list(protocols),
                "technologies": list(technologies),
                "is_multi_plane": any("GTP-U" in p for p in protocols) and any(p in ["GTP-C", "SIP", "Diameter", "PFCP"] for p in protocols),
                "total_packets": sum(f["packet_count"] for f in session_flows),
                "sample_flows": session_flows[:3] # Context for LLM
            })
            
    correlated.sort(key=lambda x: x["total_packets"], reverse=True)
    return correlated[:5] # Top 5 complex sessions for LLM context


def get_primary_technology(technologies: List[str]) -> str:
    """Determine the primary mobile technology for a flow"""
    # Priority order: 5G > 4G > 3G > 2G > Voice > Other
    priority = ["5G/NR", "5G/SBI", "4G/LTE", "3G/UMTS", "2G/GSM", "VoLTE/VoNR", "VoIP", "2G/3G/SS7"]
    for tech in priority:
        if tech in technologies:
            return tech
    return technologies[0] if technologies else "Unknown"


def get_protocol_stats(flows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Get protocol distribution statistics"""
    stats = defaultdict(int)
    
    for flow in flows:
        protocol = flow.get("protocol", "Unknown")
        stats[protocol] += flow["packet_count"]
    
    return dict(stats)


def get_technology_stats(flows: List[Dict[str, Any]]) -> Dict[str, int]:
    """Get mobile technology distribution statistics"""
    stats = defaultdict(int)
    
    for flow in flows:
        tech = flow.get("primary_tech", "Unknown")
        stats[tech] += flow["packet_count"]
    
    return dict(stats)


def get_failure_summary(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of network failures for RCA
    """
    summary = {
        "total_errors": 0,
        "error_types": defaultdict(int),
        "failed_flows": 0
    }
    
    for flow in flows:
        if flow.get("has_errors"):
            summary["failed_flows"] += 1
            for fail in flow.get("failures", []):
                summary["total_errors"] += 1
                if "sip_error" in fail:
                    summary["error_types"][f"SIP {fail['sip_error']}"] += 1
                # Add other protocols here
                
    summary["error_types"] = dict(summary["error_types"])
    return summary


def identify_telecom_sessions(flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify potential telecom sessions across all mobile technologies
    Supports 2G/3G/4G/5G protocols
    """
    sessions = []
    
    # ========== 5G Sessions ==========
    
    # PFCP Sessions (5G User Plane Function)
    pfcp_flows = [
        f for f in flows 
        if f.get("src_port") == 8805 or f.get("dst_port") == 8805
        or "PFCP" in f.get("protocol", "")
    ]
    if pfcp_flows:
        sessions.append({
            "type": "5G PFCP Session",
            "technology": "5G/NR",
            "description": "Packet Forwarding Control Protocol (N4 interface)",
            "flow_count": len(pfcp_flows),
            "total_packets": sum(f["packet_count"] for f in pfcp_flows),
            "total_bytes": sum(f["total_bytes"] for f in pfcp_flows),
        })
    
    # NGAP Sessions (5G RAN)
    ngap_flows = [
        f for f in flows 
        if f.get("src_port") == 38412 or f.get("dst_port") == 38412
        or "NGAP" in f.get("protocol", "")
    ]
    if ngap_flows:
        sessions.append({
            "type": "5G NGAP Session",
            "technology": "5G/NR",
            "description": "NG Application Protocol (N2 interface)",
            "flow_count": len(ngap_flows),
            "total_packets": sum(f["packet_count"] for f in ngap_flows),
            "total_bytes": sum(f["total_bytes"] for f in ngap_flows),
        })
    
    # ========== 4G/LTE Sessions ==========
    
    # S1-AP Sessions (4G RAN)
    s1ap_flows = [
        f for f in flows 
        if f.get("src_port") == 36412 or f.get("dst_port") == 36412
        or "S1-AP" in f.get("protocol", "")
    ]
    if s1ap_flows:
        sessions.append({
            "type": "4G S1-AP Session",
            "technology": "4G/LTE",
            "description": "S1 Application Protocol (eNB-MME)",
            "flow_count": len(s1ap_flows),
            "total_packets": sum(f["packet_count"] for f in s1ap_flows),
            "total_bytes": sum(f["total_bytes"] for f in s1ap_flows),
        })
    
    # X2-AP Sessions (4G Inter-eNB)
    x2ap_flows = [
        f for f in flows 
        if f.get("src_port") == 36422 or f.get("dst_port") == 36422
        or "X2-AP" in f.get("protocol", "")
    ]
    if x2ap_flows:
        sessions.append({
            "type": "4G X2-AP Session",
            "technology": "4G/LTE",
            "description": "X2 Application Protocol (Inter-eNB handover)",
            "flow_count": len(x2ap_flows),
            "total_packets": sum(f["packet_count"] for f in x2ap_flows),
            "total_bytes": sum(f["total_bytes"] for f in x2ap_flows),
        })
    
    # Diameter Sessions (4G/5G Signaling)
    diameter_flows = [
        f for f in flows 
        if f.get("is_diameter") or f.get("src_port") == 3868 or f.get("dst_port") == 3868
        or "Diameter" in f.get("protocol", "")
    ]
    if diameter_flows:
        sessions.append({
            "type": "Diameter Session",
            "technology": "4G/LTE",
            "description": "Diameter signaling (Gx/Gy/S6a/Rx interfaces)",
            "flow_count": len(diameter_flows),
            "total_packets": sum(f["packet_count"] for f in diameter_flows),
            "total_bytes": sum(f["total_bytes"] for f in diameter_flows),
        })
    
    # ========== 3G/4G/5G GTP Sessions ==========
    
    # GTP-U Tunnels (User Plane - all generations)
    gtp_u_flows = [f for f in flows if f.get("is_gtp") or "GTP-U" in f.get("protocol", "")]
    if gtp_u_flows:
        teids = list(set(
            teid 
            for f in gtp_u_flows 
            for teid in f.get("gtp_teids", [])
        ))
        sessions.append({
            "type": "GTP-U Tunnel",
            "technology": "3G/4G/5G",
            "description": "GPRS Tunneling Protocol - User Plane",
            "flow_count": len(gtp_u_flows),
            "total_packets": sum(f["packet_count"] for f in gtp_u_flows),
            "total_bytes": sum(f["total_bytes"] for f in gtp_u_flows),
            "teids": teids[:10],  # Limit to first 10 TEIDs
            "unique_teids": len(teids),
        })
    
    # GTP-C Sessions (Control Plane)
    gtp_c_flows = [
        f for f in flows 
        if f.get("src_port") == 2123 or f.get("dst_port") == 2123
        or "GTP-C" in f.get("protocol", "")
    ]
    if gtp_c_flows:
        sessions.append({
            "type": "GTP-C Session",
            "technology": "3G/4G",
            "description": "GPRS Tunneling Protocol - Control Plane",
            "flow_count": len(gtp_c_flows),
            "total_packets": sum(f["packet_count"] for f in gtp_c_flows),
            "total_bytes": sum(f["total_bytes"] for f in gtp_c_flows),
        })
    
    # ========== 2G/3G SS7 Sessions ==========
    
    # M3UA Sessions (SS7 over IP)
    m3ua_flows = [
        f for f in flows 
        if f.get("src_port") in (2905, 2906) or f.get("dst_port") in (2905, 2906)
        or "M3UA" in f.get("protocol", "")
    ]
    if m3ua_flows:
        sessions.append({
            "type": "M3UA/SS7 Session",
            "technology": "2G/3G",
            "description": "MTP3 User Adaptation (SS7 over IP)",
            "flow_count": len(m3ua_flows),
            "total_packets": sum(f["packet_count"] for f in m3ua_flows),
            "total_bytes": sum(f["total_bytes"] for f in m3ua_flows),
        })
    
    # ========== Voice/IMS Sessions ==========
    
    # SIP Sessions
    sip_flows = [
        f for f in flows 
        if f.get("src_port") in (5060, 5061) or f.get("dst_port") in (5060, 5061)
        or "SIP" in f.get("protocol", "")
    ]
    if sip_flows:
        sessions.append({
            "type": "SIP/VoIP Session",
            "technology": "VoLTE/VoNR",
            "description": "Session Initiation Protocol (Voice/Video calls)",
            "flow_count": len(sip_flows),
            "total_packets": sum(f["packet_count"] for f in sip_flows),
            "total_bytes": sum(f["total_bytes"] for f in sip_flows),
        })
    
    # RTP Streams (Voice/Video Media)
    rtp_flows = [f for f in flows if "RTP" in f.get("protocol", "")]
    if rtp_flows:
        sessions.append({
            "type": "RTP Media Stream",
            "technology": "VoLTE/VoNR",
            "description": "Real-time Transport Protocol (Voice/Video media)",
            "flow_count": len(rtp_flows),
            "total_packets": sum(f["packet_count"] for f in rtp_flows),
            "total_bytes": sum(f["total_bytes"] for f in rtp_flows),
        })
    
    # ========== Infrastructure Sessions ==========
    
    # RADIUS Sessions (Authentication)
    radius_flows = [
        f for f in flows 
        if f.get("src_port") in (1812, 1813) or f.get("dst_port") in (1812, 1813)
        or "RADIUS" in f.get("protocol", "")
    ]
    if radius_flows:
        sessions.append({
            "type": "RADIUS Session",
            "technology": "AAA",
            "description": "Authentication, Authorization, Accounting",
            "flow_count": len(radius_flows),
            "total_packets": sum(f["packet_count"] for f in radius_flows),
            "total_bytes": sum(f["total_bytes"] for f in radius_flows),
        })
    
    # DNS Sessions
    dns_flows = [
        f for f in flows 
        if f.get("src_port") == 53 or f.get("dst_port") == 53
        or "DNS" in f.get("protocol", "")
    ]
    if dns_flows:
        sessions.append({
            "type": "DNS Session",
            "technology": "Infrastructure",
            "description": "Domain Name System queries",
            "flow_count": len(dns_flows),
            "total_packets": sum(f["packet_count"] for f in dns_flows),
            "total_bytes": sum(f["total_bytes"] for f in dns_flows),
        })
    
    return sessions


def format_session_for_export(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format session object to match strict export schema.
    
    Schema:
    {
      "session_key": "5g:amfue=12345:seid=0xabc",
      "generation": "5G",
      "identifiers": { ... },
      "time_start": "...",
      "time_end": "...",
      "kpis": { ... },
      "linked_transactions": [...],
      "linked_flows": [...]
    }
    """
    
    # 1. Determine Generation
    gen = "Unknown"
    tech = session.get("technology", "")
    if "5G" in tech: gen = "5G"
    elif "4G" in tech: gen = "4G"
    elif "3G" in tech: gen = "3G"
    elif "2G" in tech: gen = "2G"
    
    # 2. Build Identifiers
    identifiers = {}
    
    # Example for GTP
    if "teids" in session:
        identifiers["teids"] = session["teids"]
    
    # Example for 5G PFCP/NGAP (extracted from flows if available or passed in)
    # This matches the sample "amf_ue_ngap_id"
    # Ideally this data should be enriched during identify_telecom_sessions
    
    # 3. Build Session Key
    # Construct a unique-ish string
    type_slug = session.get("type", "session").replace(" ", "_").lower()
    session_key = f"{gen.lower()}:{type_slug}:{session.get('flow_count', 0)}"
    
    # 4. KPIs
    kpis = {
        "packet_count": session.get("total_packets", 0),
        "byte_count": session.get("total_bytes", 0),
        "flow_count": session.get("flow_count", 0)
    }
    
    return {
        "session_key": session_key,
        "generation": gen,
        "type": session.get("type"), # Keep original type for debugging
        "description": session.get("description"),
        "identifiers": identifiers,
        "time_start": session.get("start_time", "N/A"), # Logic needed to persist time in session obj
        "time_end": session.get("end_time", "N/A"),
        "kpis": kpis,
        "linked_transactions": [], # Placeholder for transaction ID correlation
        "linked_flows": [] # Placeholder for flow ID correlation
    }


def extract_message_sequence(packets: List[Dict[str, Any]], max_messages: int = 100) -> List[Dict[str, Any]]:
    """
    Extract time-ordered message sequence for sequence diagram visualization.
    Groups messages by endpoint pairs and includes protocol information.
    
    Args:
        packets: List of parsed packet dictionaries
        max_messages: Maximum number of messages to return (for performance)
        
    Returns:
        List of message dictionaries sorted by timestamp
    """
    logger.info(f"Extracting message sequence from {len(packets)} packets")
    
    messages = []
    
    for pkt in packets:
        # Skip packets without IP info
        if "src_ip" not in pkt or "dst_ip" not in pkt:
            continue
        
        # Extract key information
        msg = {
            "timestamp": pkt.get("timestamp", 0),
            "src_ip": pkt["src_ip"],
            "dst_ip": pkt["dst_ip"],
            "src_port": pkt.get("src_port", 0),
            "dst_port": pkt.get("dst_port", 0),
            "protocol": pkt.get("protocol", "Unknown"),
            "transport": pkt.get("transport", "Unknown"),
            "length": pkt.get("length", 0),
            "info": pkt.get("protocol_info", ""),
        }
        
        # Add protocol-specific details
        if "gtp" in pkt:
            msg["gtp_teid"] = pkt["gtp"].get("teid")
            msg["gtp_type"] = pkt["gtp"].get("type", "Unknown")
            msg["info"] = f"GTP {msg['gtp_type']}" + (f" TEID:{msg['gtp_teid']}" if msg["gtp_teid"] else "")
        
        if "diameter" in pkt:
            msg["diameter_cmd"] = pkt["diameter"].get("command_name", "Unknown")
            msg["diameter_app"] = pkt["diameter"].get("app_id")
            msg["info"] = f"Diameter {msg['diameter_cmd']}"
        
        if "sip" in pkt:
            msg["sip_method"] = pkt["sip"].get("method", "")
            msg["sip_status"] = pkt["sip"].get("status_code", "")
            if msg["sip_method"]:
                msg["info"] = f"SIP {msg['sip_method']}"
            elif msg["sip_status"]:
                msg["info"] = f"SIP {msg['sip_status']}"
        
        if "pfcp" in pkt:
            msg["pfcp_type"] = pkt["pfcp"].get("message_type", "Unknown")
            msg["info"] = f"PFCP {msg['pfcp_type']}"
        
        messages.append(msg)
    
    # Sort by timestamp
    messages.sort(key=lambda x: x["timestamp"])
    
    # Limit to max_messages for performance
    if len(messages) > max_messages:
        logger.info(f"Limiting sequence to {max_messages} messages (from {len(messages)})")
        # Sample evenly across the timeline
        step = len(messages) // max_messages
        messages = messages[::step][:max_messages]
    
    logger.info(f"Extracted {len(messages)} messages for sequence diagram")
    return messages
