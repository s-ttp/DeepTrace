"""
Protocol Cause Code Mappings
Provides human-readable labels for standard telecom protocol cause codes.
References: 3GPP TS 29.244 (PFCP), TS 29.274 (GTPv2), TS 38.413 (NGAP),
            TS 29.229/29.272 (Diameter), TS 24.301 (NAS EMM/ESM)
"""

PFCP_CAUSES = {
    1: "Request Accepted",
    2: "Request Rejected", 
    3: "Session Context Not Found",
    4: "Mandatory IE Missing",
    5: "Conditional IE Missing",
    6: "Invalid Length",
    7: "Mandatory IE Incorrect",
    8: "Invalid Forwarding Policy",
    9: "Request Rejected (Reason not specified)",
    19: "No Established PFCP Association",
    64: "Remote Node Not Responsive",
    72: "System Failure",
    73: "No Resources Available"
}

GTPV2_CAUSES = {
    16: "Request Accepted",
    64: "Context Not Found",
    66: "No Resources Available",
    70: "System Failure",
    72: "Mandatory IE Missing",
    73: "Conditional IE Missing",
    74: "Invalid Length",
    83: "Preferred PDN Type not supported",
    84: "All dynamic addresses are occupied",
    88: "UE refuses",
    89: "Service denied",
    100: "Remote Node Not Responsive"
}

# Simplified NGAP/S1AP Cause Categories
NGAP_CAUSES = {
    # Radio Network Layer
    15: "Unspecified",
    20: "Release due to UE generated signalling connection release",
    26: "Failure in the Radio Interface Procedure",
    27: "Release due to pre-emption",
    
    # Transport Layer
    113: "Transport Resource Unavailable",
    114: "Unspecified Transport Layer Cause",
    
    # Protocol
    115: "Transfer Syntax Error",
    116: "Abstract Syntax Error (Reject)",
    118: "Message not Compatible with Receiver State"
}

# Diameter Result-Codes (RFC 6733 + 3GPP TS 29.229/29.272)
DIAMETER_RESULT_CODES = {
    # Success (2xxx)
    2001: "DIAMETER_SUCCESS",
    2002: "DIAMETER_LIMITED_SUCCESS",
    
    # Protocol Errors (3xxx)
    3001: "DIAMETER_COMMAND_UNSUPPORTED",
    3002: "DIAMETER_UNABLE_TO_DELIVER",
    3003: "DIAMETER_REALM_NOT_SERVED",
    3004: "DIAMETER_TOO_BUSY",
    3005: "DIAMETER_LOOP_DETECTED",
    3006: "DIAMETER_REDIRECT_INDICATION",
    3007: "DIAMETER_APPLICATION_UNSUPPORTED",
    3008: "DIAMETER_INVALID_HDR_BITS",
    3009: "DIAMETER_INVALID_AVP_BITS",
    3010: "DIAMETER_UNKNOWN_PEER",
    
    # Transient Failures (4xxx)
    4001: "DIAMETER_AUTHENTICATION_REJECTED",
    4002: "DIAMETER_OUT_OF_SPACE",
    4003: "ELECTION_LOST",
    
    # Permanent Failures (5xxx)
    5001: "DIAMETER_AVP_UNSUPPORTED",
    5002: "DIAMETER_UNKNOWN_SESSION_ID",
    5003: "DIAMETER_AUTHORIZATION_REJECTED",
    5004: "DIAMETER_INVALID_AVP_VALUE",
    5005: "DIAMETER_MISSING_AVP",
    5006: "DIAMETER_RESOURCES_EXCEEDED",
    5007: "DIAMETER_CONTRADICTING_AVPS",
    5008: "DIAMETER_AVP_NOT_ALLOWED",
    5009: "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES",
    5010: "DIAMETER_NO_COMMON_APPLICATION",
    5011: "DIAMETER_UNSUPPORTED_VERSION",
    5012: "DIAMETER_UNABLE_TO_COMPLY",
    5014: "DIAMETER_INVALID_BIT_IN_HEADER",
    5015: "DIAMETER_INVALID_AVP_LENGTH",
    5016: "DIAMETER_INVALID_MESSAGE_LENGTH",
    5017: "DIAMETER_INVALID_AVP_BIT_COMBO",
    5018: "DIAMETER_NO_COMMON_SECURITY",
}

# 3GPP Diameter Experimental-Result-Codes (TS 29.229, TS 29.272)
DIAMETER_3GPP_CODES = {
    # Cx/Dx Interface (IMS)
    2001: "DIAMETER_FIRST_REGISTRATION",
    2002: "DIAMETER_SUBSEQUENT_REGISTRATION",
    2003: "DIAMETER_UNREGISTERED_SERVICE",
    5001: "DIAMETER_ERROR_USER_UNKNOWN",
    5002: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
    5003: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
    5004: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
    5005: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",
    5006: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",
    5007: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
    5008: "DIAMETER_ERROR_TOO_MUCH_DATA",
    5009: "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA",
    5011: "DIAMETER_ERROR_FEATURE_UNSUPPORTED",
    
    # S6a Interface (MME-HSS)
    5401: "DIAMETER_ERROR_USER_UNKNOWN",
    5402: "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
    5420: "DIAMETER_ERROR_UNKNOWN_SERVING_NODE",
    5421: "DIAMETER_ERROR_RAT_NOT_ALLOWED",
    5450: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
}

# Diameter Application IDs for Interface Classification
DIAMETER_APP_IDS = {
    16777216: {"name": "Cx", "interface": "P-CSCF↔HSS", "description": "IMS Registration"},
    16777217: "Sh",  # HSS-AS
    16777236: {"name": "Rx", "interface": "P-CSCF↔PCRF", "description": "Policy/QoS"},
    16777238: {"name": "Gx", "interface": "PGW↔PCRF", "description": "Policy Control"},
    16777251: {"name": "S6a", "interface": "MME↔HSS", "description": "EPS Subscriber Data"},
    16777252: {"name": "S6d", "interface": "SGSN↔HSS", "description": "EPS Subscriber Data"},
    16777255: {"name": "SWx", "interface": "3GPP AAA↔HSS", "description": "Non-3GPP Access"},
    16777272: {"name": "S6b", "interface": "PGW↔3GPP AAA", "description": "Trusted WLAN"},
    4: {"name": "Ro", "interface": "OCS", "description": "Online Charging"},
    0: {"name": "Base", "interface": "Generic", "description": "Diameter Base Protocol"},
}

SIP_STATUS_CODES = {
    100: "Trying",
    180: "Ringing",
    183: "Session Progress",
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    408: "Request Timeout",
    480: "Temporarily Unavailable",
    486: "Busy Here",
    487: "Request Terminated",
    488: "Not Acceptable Here",
    500: "Server Internal Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Server Time-out",
    600: "Busy Everywhere",
    603: "Decline",
    604: "Does Not Exist Anywhere",
}

# NAS EMM Cause Codes (3GPP TS 24.301)
NAS_EMM_CAUSES = {
    2: "IMSI unknown in HSS",
    3: "Illegal UE",
    5: "IMEI not accepted",
    6: "Illegal ME",
    7: "EPS services not allowed",
    8: "EPS services and non-EPS services not allowed",
    9: "UE identity cannot be derived",
    10: "Implicitly detached",
    11: "PLMN not allowed",
    12: "Tracking Area not allowed",
    13: "Roaming not allowed in this TA",
    14: "EPS services not allowed in this PLMN",
    15: "No suitable cells in TA",
    16: "MSC temporarily not reachable",
    17: "Network failure",
    18: "CS domain not available",
    19: "ESM failure",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    25: "Not authorized for this CSG",
    35: "Requested service option not authorized in this PLMN",
    39: "CS service temporarily not available",
    40: "No EPS bearer context activated",
}

# NAS ESM Cause Codes (3GPP TS 24.301)
NAS_ESM_CAUSES = {
    8: "Operator Determined Barring",
    26: "Insufficient resources",
    27: "Missing or unknown APN",
    28: "Unknown PDN type",
    29: "User authentication failed",
    30: "Request rejected by Serving GW or PDN GW",
    31: "Request rejected, unspecified",
    32: "Service option not supported",
    33: "Requested service option not subscribed",
    34: "Service option temporarily out of order",
    35: "PTI already in use",
    36: "Regular deactivation",
    37: "EPS QoS not accepted",
    38: "Network failure",
    39: "Reactivation requested",
    41: "Semantic error in the TFT operation",
    42: "Syntactical error in the TFT operation",
    43: "Invalid EPS bearer identity",
    44: "Semantic errors in packet filter(s)",
    45: "Syntactical errors in packet filter(s)",
    46: "Unused (see annex I)",
    47: "PTI mismatch",
    50: "PDN type IPv4 only allowed",
    51: "PDN type IPv6 only allowed",
    52: "Single address bearers only allowed",
    53: "ESM information not received",
    54: "PDN connection does not exist",
    55: "Multiple PDN connections for APN not allowed",
    56: "Collision with network initiated request",
    59: "Unsupported QCI value",
    60: "Bearer handling not supported",
    65: "Maximum number of EPS bearers reached",
    66: "Requested APN not supported in current RAT",
}

def get_cause_label(protocol: str, code: int) -> str:
    """Returns the human-readable label or 'Unknown'"""
    try:
        code = int(code)
    except (ValueError, TypeError):
        return str(code)

    if protocol == "PFCP":
        return PFCP_CAUSES.get(code, f"Unknown Cause {code}")
    elif protocol in ["GTP", "GTPv2", "GTPv2-C"]:
        return GTPV2_CAUSES.get(code, f"Unknown Cause {code}")
    elif protocol in ["NGAP", "S1AP"]:
        return NGAP_CAUSES.get(code, f"Unknown Cause {code}")
    elif protocol == "SIP":
        return SIP_STATUS_CODES.get(code, f"Status {code}")
    elif protocol == "Diameter":
        # Check base codes first, then 3GPP
        label = DIAMETER_RESULT_CODES.get(code)
        if not label:
            label = DIAMETER_3GPP_CODES.get(code)
        return label if label else f"Diameter Code {code}"
    elif protocol in ["NAS-EMM", "EMM"]:
        return NAS_EMM_CAUSES.get(code, f"EMM Cause {code}")
    elif protocol in ["NAS-ESM", "ESM"]:
        return NAS_ESM_CAUSES.get(code, f"ESM Cause {code}")
    
    return str(code)

def get_diameter_interface(app_id: int) -> dict:
    """Returns interface info for a Diameter Application-ID"""
    info = DIAMETER_APP_IDS.get(app_id)
    if isinstance(info, dict):
        return info
    elif isinstance(info, str):
        return {"name": info, "interface": "Unknown", "description": ""}
    return {"name": "Unknown", "interface": f"App-ID {app_id}", "description": ""}

