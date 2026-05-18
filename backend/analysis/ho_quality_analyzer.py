"""Handover quality scoring.

Beyond pass/fail: classify HOs (X2 vs S1 for 4G, Xn vs N2 for 5G, intra-vs-inter-eNB),
measure preparation latency, and surface beam management (5G NRPPa / SSB) when
available in the radio trace.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# S1AP procedure codes (3GPP TS 36.413)
S1AP_HANDOVER_PREPARATION = 0          # HandoverRequired (source MME)
S1AP_HANDOVER_RESOURCE_ALLOCATION = 1  # HandoverRequest (target eNB)
S1AP_HANDOVER_NOTIFICATION = 2         # HandoverNotify (UE arrived at target)
S1AP_PATH_SWITCH = 3                   # PathSwitchRequest (X2 HO completion)
S1AP_HANDOVER_CANCEL = 4

# NGAP procedure codes (3GPP TS 38.413)
NGAP_HANDOVER_PREPARATION = 0
NGAP_HANDOVER_RESOURCE_ALLOCATION = 1
NGAP_HANDOVER_NOTIFICATION = 2
NGAP_PATH_SWITCH_REQUEST = 3
NGAP_HANDOVER_CANCEL = 4

_S1AP_HO_CODES = {S1AP_HANDOVER_PREPARATION, S1AP_HANDOVER_RESOURCE_ALLOCATION,
                  S1AP_HANDOVER_NOTIFICATION, S1AP_PATH_SWITCH, S1AP_HANDOVER_CANCEL}


def _proto(tx: Dict[str, Any]) -> str:
    return str(tx.get("protocol", "")).upper()


def _proc_int(tx: Dict[str, Any], key: str) -> Optional[int]:
    raw = tx.get(key)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _ts(tx: Dict[str, Any]) -> Optional[float]:
    for k in ("time_epoch", "timestamp", "frame.time_epoch"):
        v = tx.get(k)
        if v is not None:
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
    return None


def analyze_handover_quality(transactions: Iterable[Dict[str, Any]],
                              radio_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Classify HOs and measure preparation latency.

    Inputs:
      - transactions: PCAP-side transaction list (S1AP/NGAP)
      - radio_events: Groundhog normalized events (optional; used for beam mgmt)
    """
    s1ap = [t for t in (transactions or []) if _proto(t) == "S1AP"]
    ngap = [t for t in (transactions or []) if _proto(t) == "NGAP"]

    by_type: Dict[str, int] = defaultdict(int)
    prep_latencies: List[float] = []
    path_switch_count = 0
    ho_cancel_count = 0

    # Pair S1AP HandoverRequired (procCode 0) with HandoverNotify (procCode 2)
    # by MME_UE_S1AP_ID when present, else by timestamp window.
    prep_events: List[Dict[str, Any]] = []
    notify_events: List[Dict[str, Any]] = []
    for tx in s1ap:
        proc = _proc_int(tx, "s1ap.procedureCode")
        if proc is None:
            continue
        if proc == S1AP_HANDOVER_PREPARATION:
            prep_events.append(tx); by_type["S1_HANDOVER_PREPARATION"] += 1
        elif proc == S1AP_HANDOVER_RESOURCE_ALLOCATION:
            by_type["S1_HANDOVER_RESOURCE_ALLOCATION"] += 1
        elif proc == S1AP_HANDOVER_NOTIFICATION:
            notify_events.append(tx); by_type["S1_HANDOVER_NOTIFY"] += 1
        elif proc == S1AP_PATH_SWITCH:
            path_switch_count += 1; by_type["X2_HANDOVER_PATH_SWITCH"] += 1
        elif proc == S1AP_HANDOVER_CANCEL:
            ho_cancel_count += 1; by_type["S1_HANDOVER_CANCEL"] += 1

    notify_index = defaultdict(list)
    for n in notify_events:
        key = str(n.get("s1ap.MME_UE_S1AP_ID") or n.get("mme_ue_s1ap_id") or "")
        notify_index[key].append(n)

    for p in prep_events:
        key = str(p.get("s1ap.MME_UE_S1AP_ID") or p.get("mme_ue_s1ap_id") or "")
        p_ts = _ts(p)
        if not p_ts:
            continue
        candidates = notify_index.get(key, [])
        n = None
        for c in candidates:
            n_ts = _ts(c)
            if n_ts and n_ts >= p_ts:
                n = (c, n_ts); break
        if n is None and not key:
            # No paired ID — fall back to nearest notify within 10s
            best = None
            for c in notify_events:
                n_ts = _ts(c)
                if n_ts and 0 <= (n_ts - p_ts) <= 10.0:
                    if best is None or (n_ts - p_ts) < best[1] - p_ts:
                        best = (c, n_ts)
            n = best
        if n:
            prep_latencies.append((n[1] - p_ts) * 1000.0)  # ms

    # 5G NGAP path
    for tx in ngap:
        proc = _proc_int(tx, "ngap.procedureCode")
        if proc is None:
            continue
        if proc == NGAP_HANDOVER_PREPARATION:
            by_type["N2_HANDOVER_PREPARATION"] += 1
        elif proc == NGAP_HANDOVER_RESOURCE_ALLOCATION:
            by_type["N2_HANDOVER_RESOURCE_ALLOCATION"] += 1
        elif proc == NGAP_HANDOVER_NOTIFICATION:
            by_type["N2_HANDOVER_NOTIFY"] += 1
        elif proc == NGAP_PATH_SWITCH_REQUEST:
            by_type["XN_HANDOVER_PATH_SWITCH"] += 1
        elif proc == NGAP_HANDOVER_CANCEL:
            by_type["N2_HANDOVER_CANCEL"] += 1

    s1_prep = by_type.get("S1_HANDOVER_PREPARATION", 0)
    s1_done = by_type.get("S1_HANDOVER_NOTIFY", 0)
    x2_done = by_type.get("X2_HANDOVER_PATH_SWITCH", 0)
    s1_total = s1_prep + x2_done  # rough denominator: ops that started

    # 5G beam management indicators (PCI / SSB changes per radio event stream)
    beam = {"pci_changes": 0, "ssb_changes": 0}
    last_pci = None
    last_ssb = None
    for ev in radio_events or []:
        pci = ev.get("pci")
        if pci is not None and pci != last_pci and last_pci is not None:
            beam["pci_changes"] += 1
        if pci is not None:
            last_pci = pci
        raw = ev.get("raw") or {}
        ssb = raw.get("ssb_index") if isinstance(raw, dict) else None
        if ssb is not None and ssb != last_ssb and last_ssb is not None:
            beam["ssb_changes"] += 1
        if ssb is not None:
            last_ssb = ssb

    return {
        "ho_present": bool(s1ap or ngap),
        "by_type": dict(by_type),
        "s1_handovers_notified": s1_done,
        "x2_path_switch_handovers": x2_done,
        "ho_cancelled": ho_cancel_count,
        "preparation_latency_ms": {
            "count": len(prep_latencies),
            "min": round(min(prep_latencies), 1) if prep_latencies else None,
            "avg": round(sum(prep_latencies) / len(prep_latencies), 1) if prep_latencies else None,
            "max": round(max(prep_latencies), 1) if prep_latencies else None,
        },
        "beam_management": beam if (beam["pci_changes"] or beam["ssb_changes"]) else None,
    }


def format_ho_quality_context_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    if not summary or not summary.get("ho_present"):
        return "## HANDOVER QUALITY: No handover events available for quality scoring."

    lines = ["## HANDOVER QUALITY"]
    if summary["by_type"]:
        counts = ", ".join(f"{k}={v}" for k, v in summary["by_type"].items())
        lines.append(f"- Procedure counts: {counts}")
    lines.append(f"- S1 handovers notified: {summary['s1_handovers_notified']}  X2 path switches: {summary['x2_path_switch_handovers']}  cancelled: {summary['ho_cancelled']}")
    pl = summary["preparation_latency_ms"]
    if pl.get("count"):
        lines.append(f"- HO preparation latency: count={pl['count']}, min={pl['min']}ms, avg={pl['avg']}ms, max={pl['max']}ms")
    if summary.get("beam_management"):
        b = summary["beam_management"]
        lines.append(f"- 5G beam mgmt: PCI changes={b['pci_changes']}, SSB index changes={b['ssb_changes']}")
    return "\n".join(lines)
