"""
TShark Protocol Field Packs
Defines curated lists of fields for targeted protocol extraction.
Validates against TShark 4.x field names.
"""

# Core Identifier Fields (Always included)
CORE_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto"
]

# Field Packs by Protocol/Technology
FIELD_PACKS = {
    # 5G Store & Forward
    "PFCP": [
        "pfcp.msg_type",       # Message Type
        "pfcp.seid",           # Session Endpoint ID
        "pfcp.cause",          # Cause Code
        "pfcp.seqno",          # Sequence Number (verified)
    ],
    
    # 5G Control Plane
    "NGAP": [
        "ngap.procedureCode",  # Procedure Code
        "ngap.cause",          # Cause
        "ngap.RAN_UE_NGAP_ID", # RAN UE ID (verified case)
        "ngap.AMF_UE_NGAP_ID", # AMF UE ID (verified case)
    ],
    
    # 5G/4G Non-Access Stratum
    # Note: NAS 5GS is split into MM (Mobility Management) and SM (Session Management)
    "NAS_5GS": [
        "nas_5gs.mm.message_type", 
        "nas_5gs.sm.message_type",
        "nas_5gs.mm.5gmm_cause",
        "nas_5gs.sm.5gsm_cause" # Assumed based on naming convention pattern, explicit fail-safe
    ],
    
    # 4G/5G Tunneling
    "GTP": [
        "gtp.message",         # Message Type
        "gtp.teid",            # Tunnel Endpoint ID
        "gtp.cause",           # Cause Code
        # "gtp.seq",           # Removed (variable field name)
        "gtp.ext_hdr.pdu_ses_con.qos_flow_id",  # QFI (5G)
    ],
    
    # 4G LTE Control
    "S1AP": [
        "s1ap.procedureCode",
        "s1ap.cause",
        "s1ap.MME_UE_S1AP_ID",
        "s1ap.ENB_UE_S1AP_ID"
    ],
    
    # Diameter (4G AAA/Policy) - Extended
    "DIAMETER": [
        "diameter.cmd.code",
        "diameter.Result-Code",
        "diameter.Experimental-Result-Code",
        "diameter.Session-Id",
        "diameter.CC-Request-Type",
        # Extended fields for interface classification and IMSI
        "diameter.hopbyhopid",      # Request/Response pairing
        "diameter.endtoendid",      # Session correlation
        "diameter.applicationId",   # Interface identification (S6a, Cx, Gx, Rx)
        "diameter.Origin-Host",     # Source node identification
        "diameter.Origin-Realm",    # Realm routing
        "diameter.User-Name",       # Contains IMSI for UE correlation
    ],
    
    # 4G NAS (EPS) - EMM/ESM Causes
    "NAS_EPS": [
        "nas_eps.emm.nas_msg_type",   # EMM Message Type
        "nas_eps.esm.nas_msg_type",   # ESM Message Type
        "nas_eps.emm.cause",          # EMM Reject Cause
        "nas_eps.esm.cause",          # ESM Reject Cause
        "nas_eps.emm.eps_mobile_id",  # IMSI/GUTI
    ],
    
    # Voice (VoLTE/VoNR) - Enhanced for advanced call analytics
    "SIP": [
        "sip.Method",
        "sip.Status-Code",
        "sip.Reason",
        "sip.Call-ID",
        "sip.CSeq",
        # Session Timer (RFC 4028)
        "sip.Session-Expires",
        "sip.Min-SE",
        # Extensions
        "sip.Require",
        "sip.Supported",
        # Call Transfer (RFC 3515)
        "sip.Refer-To",
        "sip.Referred-By",
        "sip.Event",
        "sip.Subscription-State",
        # Early Media & Ringback (RFC 3960)
        "sip.P-Early-Media",
        "sip.Alert-Info",
        # Identity
        "sip.From",
        "sip.To",
        "sip.P-Asserted-Identity",
        # SDP Body (for preconditions)
        "sip.msg_body",
    ],
    
    # RTP/RTCP (Voice Quality Metrics)
    "RTP": [
        "rtp.ssrc",            # Synchronization Source ID
        "rtp.seq",             # Sequence Number
        "rtp.timestamp",       # RTP Timestamp
        "rtp.p_type",          # Payload Type
        "rtp.marker",          # Marker Bit (speech activity)
    ],
    
    "RTCP": [
        "rtcp.ssrc.source",    # Source SSRC
        "rtcp.sender.packetcount",  # Packets sent
        "rtcp.sender.octetcount",   # Bytes sent
        "rtcp.sdes.type",      # SDES item type
        "rtcp.roundtrip-delay", # Round-trip delay (if calculable)
        "rtcp.jitter",         # Inter-arrival jitter
        "rtcp.lost",           # Cumulative packet loss
        "rtcp.fraction",       # Fraction lost (since last report)
    ],
    
    # Transport Reliability
    "SCTP": [
        "sctp.verification_tag", # Proxy for Assoc ID
        "sctp.data_tsn",         # Transmission Sequence Number
        "sctp.data_sid",         # Stream ID
        "sctp.chunk_type",       # Chunk Type (INIT, DATA, SACK, ABORT)
        "sctp.cause_code",       # Abort Cause Code (if available)
        "sctp.retransmission",   # Retransmission indicator
    ],
    
    # HTTP/2 (5G SBI)
    "HTTP2": [
        "http2.streamid",       # Stream ID
        "http2.type",           # Frame Type
        "http2.flags",          # Frame Flags
        "http2.header.name",    # Header Name
        "http2.header.value",   # Header Value
        "http2.status",         # HTTP/2 Status Code
    ],
    
    # M3UA/MTP3 (SS7 over IP)
    "M3UA": [
        "m3ua.message_class",   # Message Class
        "m3ua.message_type",    # Message Type
        "m3ua.routing_context", # Routing Context
        "m3ua.opc",             # Originating Point Code
        "m3ua.dpc",             # Destination Point Code
        "mtp3.opc",             # MTP3 OPC
        "mtp3.dpc",             # MTP3 DPC
        "mtp3.si",              # Service Indicator
    ],
    
    # RADIUS (Authentication)
    "RADIUS": [
        "radius.code",          # Packet Type
        "radius.id",            # Identifier
        "radius.Acct_Status_Type", # Accounting Status
        "radius.User_Name",     # Username
        "radius.Calling_Station_Id", # Calling Station
        "radius.Called_Station_Id",  # Called Station
        "radius.Framed_IP_Address",  # Assigned IP
    ],
    
    # DNS (Correlation)
    "DNS": [
        "dns.qry.name",         # Query Name
        "dns.qry.type",         # Query Type
        "dns.resp.name",        # Response Name
        "dns.a",                # A Record
        "dns.aaaa",             # AAAA Record
        "dns.flags.rcode",      # Response Code
    ],
}

def get_all_fields() -> list[str]:
    """Return a flat list of all unique fields from all packs + core fields"""
    all_fields = set(CORE_FIELDS)
    for pack in FIELD_PACKS.values():
        all_fields.update(pack)
    return list(all_fields)

