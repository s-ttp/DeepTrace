"""
RAN Analysis Taxonomy - Enums and Constants

Defines shared types for issue classification, severity, and confidence levels.
"""
from enum import Enum
from typing import Dict, Any


class Generation(str, Enum):
    """Mobile network generation"""
    G2 = "2G"
    G3 = "3G"
    G4 = "4G"
    G5 = "5G"
    UNKNOWN = "Unknown"


class Protocol(str, Enum):
    """RAN signaling protocols"""
    # 2G
    BSSAP = "BSSAP"
    DTAP = "DTAP"
    RR = "RR"
    # 3G
    RANAP = "RANAP"
    RRC_3G = "RRC"
    NBAP = "NBAP"
    # 4G
    S1AP = "S1AP"
    X2AP = "X2AP"
    # 5G
    NGAP = "NGAP"
    XNAP = "XnAP"
    # Transport
    SCTP = "SCTP"
    SCCP = "SCCP"


class IssueType(str, Enum):
    """RAN issue types for detection"""
    RADIO_LINK_FAILURE = "RADIO_LINK_FAILURE"
    UE_CONTEXT_RELEASE = "UE_CONTEXT_RELEASE"
    HANDOVER_FAILURE = "HANDOVER_FAILURE"
    PAGING_FAILURE = "PAGING_FAILURE"
    ACCESS_FAILURE = "ACCESS_FAILURE"
    RAB_ERAB_QOS_FAILURE = "RAB_ERAB_QOS_FAILURE"
    REDIRECTION_FALLBACK = "REDIRECTION_FALLBACK"
    SIGNALING_CONGESTION = "SIGNALING_CONGESTION"
    TRANSPORT_INSTABILITY = "TRANSPORT_INSTABILITY"


class Severity(str, Enum):
    """Issue severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence levels for findings"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Procedure code mappings for human-readable labels
S1AP_PROCEDURES: Dict[int, str] = {
    0: "HandoverPreparation",
    1: "HandoverResourceAllocation",
    2: "HandoverNotification",
    3: "PathSwitchRequest",
    4: "HandoverCancel",
    9: "InitialContextSetup",
    10: "InitialContextSetupFailure",
    17: "UECapabilityInfoIndication",
    21: "UEContextReleaseRequest",
    23: "UEContextRelease",
    24: "UEContextReleaseCommand",
    25: "UEContextModification",
    5: "E-RABSetup",
    6: "E-RABModify",
    7: "E-RABRelease",
    8: "E-RABReleaseIndication",
    14: "Paging",
    12: "InitialUEMessage",
    13: "DownlinkNASTransport",
    27: "UplinkNASTransport",
}

NGAP_PROCEDURES: Dict[int, str] = {
    12: "HandoverPreparation",
    13: "HandoverResourceAllocation",
    14: "HandoverNotification",
    15: "PathSwitchRequest",
    16: "HandoverCancel",
    14: "InitialContextSetup",
    41: "UEContextRelease",
    42: "UEContextReleaseRequest",
    43: "UEContextModification",
    26: "PDUSessionResourceSetup",
    27: "PDUSessionResourceModify",
    28: "PDUSessionResourceRelease",
    36: "Paging",
    15: "InitialUEMessage",
    25: "DownlinkNASTransport",
    46: "UplinkNASTransport",
}

# Cause codes indicating radio-related failures
RADIO_CAUSE_KEYWORDS = [
    "radio", "rlf", "radio link failure", "radio network layer failure",
    "radio connection", "radio resources", "handover cancelled",
    "handover failure", "ho failure", "lost coverage",
    "user inactivity", "release due to", "connection with ue lost"
]

HANDOVER_CAUSE_KEYWORDS = [
    "handover", "ho failure", "ho cancelled", "relocation",
    "target not allowed", "no radio resources", "resource unavailable"
]

CONGESTION_CAUSE_KEYWORDS = [
    "congestion", "overload", "no resources", "resource unavailable",
    "capacity exceeded", "reject"
]


def get_procedure_label(protocol: str, code: int) -> str:
    """Get human-readable procedure label"""
    if protocol == "S1AP":
        return S1AP_PROCEDURES.get(code, f"ProcedureCode_{code}")
    elif protocol == "NGAP":
        return NGAP_PROCEDURES.get(code, f"ProcedureCode_{code}")
    return f"{protocol}_Procedure_{code}"
