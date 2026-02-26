"""
RAN TShark Field Packs

Defines display filters and fields for each generation/protocol.
Used by extractor.py to run targeted TShark extraction.
"""
from typing import Dict, List, Tuple

# Field pack structure: (display_filter, list_of_fields)
RAN_FIELD_PACKS: Dict[str, Tuple[str, List[str]]] = {
    # 4G LTE: S1AP
    "S1AP": (
        "s1ap",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sctp.verification_tag",
            "sctp.data_sid",
            "s1ap.procedureCode",
            "s1ap.MME_UE_S1AP_ID",
            "s1ap.ENB_UE_S1AP_ID",
            "s1ap.Cause",
            "s1ap.cause.radioNetwork",
            "s1ap.cause.transport",
            "s1ap.cause.nas",
            "s1ap.cause.protocol",
            "s1ap.cause.misc",
        ]
    ),
    
    # 5G NR: NGAP
    "NGAP": (
        "ngap",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sctp.verification_tag",
            "sctp.data_sid",
            "ngap.procedureCode",
            "ngap.AMF_UE_NGAP_ID",
            "ngap.RAN_UE_NGAP_ID",
            "ngap.Cause",
            "ngap.cause.radioNetwork",
            "ngap.cause.transport",
            "ngap.cause.nas",
            "ngap.cause.protocol",
            "ngap.cause.misc",
        ]
    ),
    
    # 4G Inter-eNB: X2AP
    "X2AP": (
        "x2ap",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sctp.verification_tag",
            "x2ap.procedureCode",
            "x2ap.Cause",
        ]
    ),
    
    # 5G Inter-gNB: XnAP
    "XnAP": (
        "xnap",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sctp.verification_tag",
            "xnap.procedureCode",
            "xnap.Cause",
        ]
    ),
    
    # 3G UMTS: RANAP (Iu interface)
    "RANAP": (
        "ranap",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sctp.verification_tag",
            "sccp.calling.ssn",
            "sccp.called.ssn",
            "ranap.procedureCode",
            "ranap.Cause",
            "ranap.RAB_ID",
        ]
    ),
    
    # 2G GSM: BSSAP/DTAP
    "BSSAP": (
        "bssap || gsm_a.dtap",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sccp.calling.ssn",
            "sccp.called.ssn",
            "bssap.pdu_type",
            "bssap.msgtype",
            "gsm_a.dtap.msg_rr_type",
            "gsm_a.dtap.msg_mm_type",
            "gsm_a.dtap.msg_cc_type",
            "bssap.cause",
        ]
    ),
    
    # Transport: SCTP (for instability detection)
    "SCTP": (
        "sctp",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sctp.verification_tag",
            "sctp.chunk_type",
            "sctp.cause_code",
            "sctp.retransmission",
        ]
    ),
    
    # Transport: SCCP (for 2G/3G correlation)
    "SCCP": (
        "sccp",
        [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "sccp.message_type",
            "sccp.calling.ssn",
            "sccp.called.ssn",
            "sccp.release_cause",
        ]
    ),
}


def get_all_ran_fields() -> List[str]:
    """Get flat list of all RAN fields for capability validation"""
    all_fields = set()
    for _, fields in RAN_FIELD_PACKS.values():
        all_fields.update(fields)
    return list(all_fields)


def get_protocol_filter(protocol: str) -> str:
    """Get TShark display filter for a protocol"""
    if protocol in RAN_FIELD_PACKS:
        return RAN_FIELD_PACKS[protocol][0]
    return protocol.lower()


def get_protocol_fields(protocol: str) -> List[str]:
    """Get field list for a protocol"""
    if protocol in RAN_FIELD_PACKS:
        return RAN_FIELD_PACKS[protocol][1]
    return []
