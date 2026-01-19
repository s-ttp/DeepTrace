"""
PCAP file parser using Scapy - Supporting 2G/3G/4G/5G Mobile Technologies

ARCHITECTURE NOTE:
- SCAPY is the PRIMARY ENGINE for: Packet iteration, flow aggregation (5-tuple), L2/L3 basic decoding, and metrics.
- TSHARK is an OPTIONAL ENRICHMENT LAYER for: Deep protocol decoding (NGAP, PFCP, NAS), expert findings, and precise cause codes.
"""
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, SCTP, Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.l2 import Ether
from typing import List, Dict, Any, Tuple
import logging
import struct

logger = logging.getLogger(__name__)

# ============================================================================
# Protocol Port Mappings for Mobile Technologies
# ============================================================================

# 2G/GSM Protocols
GSM_PORTS = {
    2905: "M3UA",           # MTP3 User Adaptation
    2906: "M3UA",
    14001: "SUA",           # SCCP User Adaptation
}

# 3G/UMTS Protocols  
UMTS_PORTS = {
    2123: "GTP-C",          # GTP Control Plane (3G/4G)
    2152: "GTP-U",          # GTP User Plane (3G/4G/5G)
    3386: "GTP-C'",         # GTP Prime (Charging)
}

# 4G/LTE Protocols
LTE_PORTS = {
    3868: "Diameter",       # Diameter (Gx, Gy, Rx, S6a, etc.)
    36412: "S1-AP",         # S1 Application Protocol
    36422: "X2-AP",         # X2 Application Protocol
    36443: "M2-AP",         # M2 Application Protocol
}

# 5G Protocols
FIVE_G_PORTS = {
    8805: "PFCP",           # Packet Forwarding Control Protocol
    38412: "NGAP",          # NG Application Protocol
    38422: "XnAP",          # Xn Application Protocol
    38462: "E1AP",          # E1 Application Protocol
    38472: "F1AP",          # F1 Application Protocol
    38482: "W1AP",          # W1 Application Protocol
    # 5G SBI uses standard HTTP/2 on 80/443
}

# Voice/IMS Protocols
VOICE_PORTS = {
    5060: "SIP",            # Session Initiation Protocol
    5061: "SIP-TLS",        # SIP over TLS
    2427: "MGCP",           # Media Gateway Control Protocol
    2727: "MGCP",
    2944: "Megaco/H.248",   # Megaco/H.248
    2945: "Megaco/H.248",
}

# RTP typically uses dynamic ports (16384-32767), detected by payload
RTP_PORT_RANGE = (16384, 32767)

# Common Infrastructure Protocols
INFRA_PORTS = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    636: "LDAPS",
    1812: "RADIUS",
    1813: "RADIUS-Acct",
    3799: "RADIUS-DynAuth",
}

# Web/API Protocols
WEB_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Combine all port mappings
ALL_PORTS = {
    **GSM_PORTS, **UMTS_PORTS, **LTE_PORTS, **FIVE_G_PORTS,
    **VOICE_PORTS, **INFRA_PORTS, **WEB_PORTS
}

# ============================================================================
# Protocol Detection - Try to import Scapy contrib modules
# ============================================================================

# GTP Support
try:
    from scapy.contrib.gtp import GTPHeader, GTP_U_Header
    GTP_AVAILABLE = True
except ImportError:
    GTP_AVAILABLE = False
    logger.warning("GTP support not available")

# Diameter Support
try:
    from scapy.contrib.diameter import Diameter
    DIAMETER_AVAILABLE = True
except ImportError:
    DIAMETER_AVAILABLE = False
    # Create a placeholder class to prevent NameError when checking haslayer()
    class Diameter:
        pass
    logger.warning("Diameter support not available")

# SCTP Support (for SS7/Diameter/S1-AP)
SCTP_AVAILABLE = True  # SCTP is in scapy.all

# ============================================================================
# Mobile Technology Detection
# ============================================================================

def detect_mobile_technology(port: int, protocol: str) -> str:
    """Detect the mobile technology generation based on port and protocol"""
    if port in GSM_PORTS or protocol in ["M3UA", "SUA", "MAP", "ISUP"]:
        return "2G/GSM"
    elif port in [2123, 3386] or protocol in ["GTP-C", "GTP-C'", "RANAP"]:
        return "3G/UMTS"
    elif port in LTE_PORTS or protocol in ["S1-AP", "X2-AP", "Diameter"]:
        return "4G/LTE"
    elif port in FIVE_G_PORTS or protocol in ["PFCP", "NGAP", "XnAP", "HTTP/2-SBI"]:
        return "5G/NR"
    elif port in VOICE_PORTS or protocol in ["SIP", "RTP", "MGCP", "Megaco"]:
        return "VoLTE/VoNR"
    return "Unknown"


def get_protocol_name(packet) -> Tuple[str, str, Dict]:
    """
    Determine the protocol name from packet layers
    Returns: (protocol_name, technology, extra_info)
    """
    protocols = []
    technology = "Unknown"
    extra_info = {}
    analysis_info = {}  # New field for RCA findings
    
    # Get layers for analysis
    raw_payload = bytes(packet[Raw]) if packet.haslayer(Raw) else b""
    
    # Get ports for protocol detection
    sport, dport = 0, 0
    if packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif packet.haslayer(SCTP):
        sport = packet[SCTP].sport
        dport = packet[SCTP].dport
    
    # ========== Telecom Protocol Detection ==========
    
    # GTP Detection (3G/4G/5G User and Control Plane)
    if GTP_AVAILABLE:
        if packet.haslayer(GTPHeader):
            gtp = packet[GTPHeader]
            msg_type = getattr(gtp, 'gtp_type', None)
            if msg_type and msg_type == 255:  # G-PDU
                protocols.append("GTP-U")
                technology = "3G/4G/5G"
            else:
                protocols.append("GTP-C")
                technology = "3G/4G"
            extra_info["gtp_teid"] = getattr(gtp, 'teid', None)
            
            # Simple GTP Cause Code Extraction (Heuristic)
            # GTP-C Response often has Cause (byte 1) in payload
            if protocols[-1] == "GTP-C" and len(raw_payload) > 8:
                # This is a simplification; real GTP parsing is complex
                # We assume if it's a response (msg type even usually), check for failure causes
                pass 
    
    # Port-based GTP detection
    if 2152 in (sport, dport):
        if "GTP-U" not in protocols:
            protocols.append("GTP-U")
        technology = "3G/4G/5G"
    if 2123 in (sport, dport):
        if "GTP-C" not in protocols:
            protocols.append("GTP-C")
        technology = "3G/4G"
    
    # PFCP Detection (5G)
    if 8805 in (sport, dport):
        protocols.append("PFCP")
        technology = "5G/NR"
    
    # Diameter Detection (4G/5G)
    if DIAMETER_AVAILABLE and packet.haslayer(Diameter):
        protocols.append("Diameter")
        technology = "4G/LTE"
    if 3868 in (sport, dport):
        if "Diameter" not in protocols:
            protocols.append("Diameter")
        technology = "4G/LTE"
        
        # Diameter Result-Code extraction
        if packet.haslayer(Diameter):
             try:
                 # Scapy Diameter parsing might vary, try to find Result-Code AVP (268)
                 # This is best effort
                 pass
             except:
                 pass
    
    # NGAP/S1-AP Detection (5G/4G RAN)
    if 38412 in (sport, dport):
        protocols.append("NGAP")
        technology = "5G/NR"
    if 36412 in (sport, dport):
        protocols.append("S1-AP")
        technology = "4G/LTE"
    if 36422 in (sport, dport):
        protocols.append("X2-AP")
        technology = "4G/LTE"
    if 38422 in (sport, dport):
        protocols.append("XnAP")
        technology = "5G/NR"
    
    # M3UA/SUA Detection (SS7 over IP - 2G/3G)
    if sport in (2905, 2906) or dport in (2905, 2906):
        protocols.append("M3UA")
        technology = "2G/3G/SS7"
    if 14001 in (sport, dport):
        protocols.append("SUA")
        technology = "2G/3G/SS7"
    
    # ========== Voice/IMS Protocol Detection ==========
    
    # SIP Detection
    if 5060 in (sport, dport) or 5061 in (sport, dport) or packet.haslayer("SIP"):
        protocols.append("SIP")
        technology = "VoLTE/VoNR"
        
        # SIP Status Code Extraction from Raw Payload
        if raw_payload:
            try:
                decoded = raw_payload.decode('utf-8', errors='ignore')
                # Look for status line: "SIP/2.0 403 Forbidden"
                if match := __import__("re").search(r"SIP/2\.0 (\d{3}) (.+?)\r\n", decoded):
                    code = int(match.group(1))
                    reason = match.group(2)
                    if code >= 400:
                        analysis_info["sip_error"] = f"{code} {reason}"
                        analysis_info["failure_code"] = code
                        extra_info["sip_status"] = code
            except Exception:
                pass
    
    # RTP Detection (voice/video media)
    if packet.haslayer(UDP):
        if RTP_PORT_RANGE[0] <= sport <= RTP_PORT_RANGE[1] or \
           RTP_PORT_RANGE[0] <= dport <= RTP_PORT_RANGE[1]:
            # Check RTP header pattern
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw])
                if len(payload) >= 12:
                    # RTP version should be 2
                    version = (payload[0] >> 6) & 0x03
                    if version == 2:
                        protocols.append("RTP")
                        technology = "VoLTE/VoNR"
                        extra_info["rtp_pt"] = payload[1] & 0x7F  # Payload type
    
    # MGCP/Megaco
    if sport in (2427, 2727) or dport in (2427, 2727):
        protocols.append("MGCP")
        technology = "VoIP"
    if sport in (2944, 2945) or dport in (2944, 2945):
        protocols.append("Megaco/H.248")
        technology = "VoIP"
    
    # ========== Infrastructure Protocol Detection ==========
    
    # DNS
    if packet.haslayer(DNS):
        protocols.append("DNS")
    elif 53 in (sport, dport):
        protocols.append("DNS")
    
    # RADIUS
    if sport in (1812, 1813, 3799) or dport in (1812, 1813, 3799):
        protocols.append("RADIUS")
        technology = "AAA"
    
    # DHCP
    if sport in (67, 68) or dport in (67, 68):
        protocols.append("DHCP")
    
    # HTTP/HTTPS
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        protocols.append("HTTP")
    elif 80 in (sport, dport) or 8080 in (sport, dport):
        if not protocols:
            protocols.append("HTTP")
    elif 443 in (sport, dport) or 8443 in (sport, dport):
        if not protocols:
            protocols.append("HTTPS")
            # Could be 5G SBI
            if technology == "Unknown":
                technology = "5G/SBI"
    
    # ========== Transport Layer ==========
    
    if not protocols:
        if packet.haslayer(SCTP):
            protocols.append("SCTP")
            # SCTP often used for telecom signaling
            technology = "Signaling"
        elif packet.haslayer(TCP):
            protocols.append("TCP")
        elif packet.haslayer(UDP):
            protocols.append("UDP")
        elif packet.haslayer(ICMP):
            protocols.append("ICMP")
    
    protocol_str = "/".join(protocols) if protocols else "Unknown"
    return protocol_str, technology, extra_info, analysis_info


def parse_pcap(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse PCAP file and extract packet information
    Supports 2G/3G/4G/5G mobile protocols
    
    Args:
        file_path: Path to the PCAP file
        
    Returns:
        List of parsed packet dictionaries
    """
    logger.info(f"Parsing PCAP file: {file_path}")
    
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        raise ValueError(f"Failed to read PCAP file: {e}")
    
    parsed_packets = []
    
    for i, pkt in enumerate(packets):
        try:
            # Get protocol, technology, and extra info
            protocol, technology, extra_info, analysis_info = get_protocol_name(pkt)
            
            packet_info = {
                "index": i,
                "timestamp": float(pkt.time),
                "length": len(pkt),
                "protocol": protocol,
                "technology": technology,
            }
            
            # Add extra protocol info
            if extra_info:
                packet_info["protocol_info"] = extra_info
            
            # Add analysis info for RCA
            if analysis_info:
                packet_info["analysis_info"] = analysis_info
            
            # Extract IP layer
            if pkt.haslayer(IP):
                packet_info["src_ip"] = pkt[IP].src
                packet_info["dst_ip"] = pkt[IP].dst
                packet_info["ip_proto"] = pkt[IP].proto
                packet_info["ttl"] = pkt[IP].ttl
            
            # Extract TCP layer
            if pkt.haslayer(TCP):
                packet_info["src_port"] = pkt[TCP].sport
                packet_info["dst_port"] = pkt[TCP].dport
                packet_info["transport"] = "TCP"
                packet_info["tcp_flags"] = str(pkt[TCP].flags)
            
            # Extract UDP layer
            elif pkt.haslayer(UDP):
                packet_info["src_port"] = pkt[UDP].sport
                packet_info["dst_port"] = pkt[UDP].dport
                packet_info["transport"] = "UDP"
            
            # Extract SCTP layer (used by many telecom protocols)
            elif pkt.haslayer(SCTP):
                packet_info["src_port"] = pkt[SCTP].sport
                packet_info["dst_port"] = pkt[SCTP].dport
                packet_info["transport"] = "SCTP"
            
            # Extract GTP info if available
            if GTP_AVAILABLE and pkt.haslayer(GTPHeader):
                gtp_layer = pkt[GTPHeader]
                packet_info["gtp"] = {
                    "version": getattr(gtp_layer, 'version', None),
                    "teid": getattr(gtp_layer, 'teid', None),
                    "length": getattr(gtp_layer, 'length', None),
                    "type": getattr(gtp_layer, 'gtp_type', None),
                }
            
            # Extract Diameter info if available
            if DIAMETER_AVAILABLE and pkt.haslayer(Diameter):
                dia_layer = pkt[Diameter]
                packet_info["diameter"] = {
                    "cmd_code": getattr(dia_layer, 'cmd_code', None),
                    "app_id": getattr(dia_layer, 'app_id', None),
                    "flags": getattr(dia_layer, 'flags', None),
                }
            
            # Extract DNS info
            if pkt.haslayer(DNS):
                dns_layer = pkt[DNS]
                packet_info["dns"] = {
                    "qr": dns_layer.qr,  # 0=query, 1=response
                    "opcode": dns_layer.opcode,
                }
            
            parsed_packets.append(packet_info)
            
        except Exception as e:
            logger.warning(f"Error parsing packet {i}: {e}")
            # Still include basic info
            parsed_packets.append({
                "index": i,
                "timestamp": float(pkt.time) if hasattr(pkt, 'time') else 0,
                "length": len(pkt),
                "protocol": "Unknown",
                "technology": "Unknown",
                "error": str(e)
            })
    
    logger.info(f"Parsed {len(parsed_packets)} packets")
    
    # Log technology summary
    tech_counts = {}
    for pkt in parsed_packets:
        tech = pkt.get("technology", "Unknown")
        tech_counts[tech] = tech_counts.get(tech, 0) + 1
    logger.info(f"Technologies detected: {tech_counts}")
    
    return parsed_packets
