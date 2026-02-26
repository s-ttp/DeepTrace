"""
Normalized Radio Event Schema for Groundhog/CovMo traces.

All Groundhog formats are normalized to this schema before analysis.
"""
from typing import Optional, Dict, Any, List


# Normalized radio event as a plain dict factory.
# Using dicts (not Pydantic) for speed and JSON compatibility.

def make_radio_event(
    time_epoch: float,
    event_type: str,
    event_label: str = "",
    time_text: str = "",
    timezone: str = "",
    generation: str = "UNKNOWN",
    rat: str = "UNKNOWN",
    cell_id: Optional[str] = None,
    tac: Optional[str] = None,
    pci: Optional[str] = None,
    earfcn: Optional[str] = None,
    nrarfcn: Optional[str] = None,
    imsi: Optional[str] = None,
    guti: Optional[str] = None,
    tmsi: Optional[str] = None,
    ue_ip: Optional[str] = None,
    rsrp: Optional[float] = None,
    rsrq: Optional[float] = None,
    sinr: Optional[float] = None,
    cqi: Optional[float] = None,
    ta: Optional[float] = None,
    dl_bler: Optional[float] = None,
    ul_bler: Optional[float] = None,
    throughput_dl_kbps: Optional[float] = None,
    throughput_ul_kbps: Optional[float] = None,
    handover: Optional[Dict[str, Any]] = None,
    paging: Optional[Dict[str, Any]] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a normalized radio event dictionary."""
    return {
        "time_epoch": time_epoch,
        "time_text": time_text,
        "timezone": timezone,
        "event_type": event_type,
        "event_label": event_label,
        "generation": generation,
        "rat": rat,
        "cell_id": cell_id,
        "tac": tac,
        "pci": pci,
        "earfcn": earfcn,
        "nrarfcn": nrarfcn,
        "imsi": imsi,
        "guti": guti,
        "tmsi": tmsi,
        "ue_ip": ue_ip,
        "rsrp": rsrp,
        "rsrq": rsrq,
        "sinr": sinr,
        "cqi": cqi,
        "ta": ta,
        "dl_bler": dl_bler,
        "ul_bler": ul_bler,
        "throughput_dl_kbps": throughput_dl_kbps,
        "throughput_ul_kbps": throughput_ul_kbps,
        "handover": handover,
        "paging": paging,
        "raw": raw or {},
    }


# Known event types for classification
EVENT_TYPES = {
    "RLF": "Radio Link Failure",
    "HO_ATTEMPT": "Handover Attempt",
    "HO_SUCCESS": "Handover Success",
    "HO_FAIL": "Handover Failure",
    "CSFB": "CS Fallback",
    "SRVCC": "Single Radio Voice Call Continuity",
    "PAGING": "Paging",
    "RRC_SETUP": "RRC Connection Setup",
    "RRC_RELEASE": "RRC Connection Release",
    "RRC_REESTABLISHMENT": "RRC Re-establishment",
    "ATTACH": "Attach",
    "DETACH": "Detach",
    "TAU": "Tracking Area Update",
    "SERVICE_REQUEST": "Service Request",
    "PDN_CONNECT": "PDN Connectivity",
    "BEARER_SETUP": "Bearer Setup",
    "BEARER_RELEASE": "Bearer Release",
    "MEASUREMENT_REPORT": "Measurement Report",
}

# Generation / RAT mapping from event hints
GENERATION_HINTS = {
    "LTE": ("4G", "EUTRAN"),
    "4G": ("4G", "EUTRAN"),
    "EUTRAN": ("4G", "EUTRAN"),
    "E-UTRAN": ("4G", "EUTRAN"),
    "NR": ("5G", "NR"),
    "5G": ("5G", "NR"),
    "5G-NR": ("5G", "NR"),
    "WCDMA": ("3G", "UTRAN"),
    "3G": ("3G", "UTRAN"),
    "UTRAN": ("3G", "UTRAN"),
    "UMTS": ("3G", "UTRAN"),
    "GSM": ("2G", "GERAN"),
    "2G": ("2G", "GERAN"),
    "GERAN": ("2G", "GERAN"),
    "GPRS": ("2G", "GERAN"),
    "EDGE": ("2G", "GERAN"),
}
