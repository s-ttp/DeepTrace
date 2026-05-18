"""5G Network Slicing & QoS Flow analysis.

Tracks S-NSSAI (slice identifier) and QFI (QoS Flow Identifier) across NGAP
and PFCP transactions. Surfaces per-slice success/failure rates and per-QFI
bearer outcomes — critical for enterprise / IoT slice deployments.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger(__name__)


def _proto(tx: Dict[str, Any]) -> str:
    return str(tx.get("protocol", "")).upper()


def _is_failure_cause(tx: Dict[str, Any]) -> bool:
    """Best-effort: a tx has a non-success outcome if status is failure
    or a cause field is set with a non-trivial value."""
    if str(tx.get("status", "")).lower() == "failure":
        return True
    for k in ("pfcp.cause", "ngap.cause", "cause"):
        v = tx.get(k)
        try:
            if v is not None and int(v) >= 64:
                return True
        except (TypeError, ValueError):
            pass
    return False


def analyze_slicing(transactions: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-S-NSSAI and per-QFI activity."""
    txs = list(transactions or [])

    # Per slice
    slice_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"messages": 0, "failures": 0})
    qfi_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"messages": 0, "failures": 0})
    sessions_with_slice = 0
    sessions_with_qfi = 0
    pdu_session_types: Dict[str, int] = defaultdict(int)

    for tx in txs:
        snssai = tx.get("ngap.SNSSAI") or tx.get("pfcp.snssai") or tx.get("snssai") or tx.get("ngap.snssai")
        qfi = tx.get("gtp.ext_hdr.pdu_ses_con.qos_flow_id") or tx.get("pfcp.qfi") or tx.get("qfi")
        pdu_type = tx.get("ngap.PDUSessionType") or tx.get("pdu_session_type")

        if snssai:
            key = str(snssai)
            slice_stats[key]["messages"] += 1
            if _is_failure_cause(tx):
                slice_stats[key]["failures"] += 1
            sessions_with_slice += 1

        if qfi is not None and qfi != "":
            key = str(qfi)
            qfi_stats[key]["messages"] += 1
            if _is_failure_cause(tx):
                qfi_stats[key]["failures"] += 1
            sessions_with_qfi += 1

        if pdu_type:
            pdu_session_types[str(pdu_type)] += 1

    if not (slice_stats or qfi_stats or pdu_session_types):
        return {"slicing_present": False}

    def _rate(d: Dict[str, int]) -> Dict[str, Any]:
        total = d["messages"] or 1
        return {
            "messages": d["messages"],
            "failures": d["failures"],
            "failure_rate_pct": round(100.0 * d["failures"] / total, 1),
        }

    return {
        "slicing_present": True,
        "slices_observed": len(slice_stats),
        "qfi_observed": len(qfi_stats),
        "per_slice": {k: _rate(v) for k, v in slice_stats.items()},
        "per_qfi": {k: _rate(v) for k, v in qfi_stats.items()},
        "pdu_session_types": dict(pdu_session_types),
    }


def format_slicing_context_for_llm(summary: Optional[Dict[str, Any]]) -> str:
    if not summary or not summary.get("slicing_present"):
        return "## NETWORK SLICING / QOS FLOWS: No 5G slice (S-NSSAI) or QFI activity observed."

    lines = ["## NETWORK SLICING / QOS FLOWS",
             f"- S-NSSAI observed: {summary['slices_observed']}  QFI observed: {summary['qfi_observed']}"]
    if summary["per_slice"]:
        lines.append("- Per-slice activity:")
        for sn, info in list(summary["per_slice"].items())[:5]:
            lines.append(f"  - S-NSSAI {sn}: msgs={info['messages']} fail={info['failures']} ({info['failure_rate_pct']}%)")
    if summary["per_qfi"]:
        lines.append("- Per-QFI activity:")
        for qfi, info in list(summary["per_qfi"].items())[:5]:
            lines.append(f"  - QFI {qfi}: msgs={info['messages']} fail={info['failures']} ({info['failure_rate_pct']}%)")
    if summary["pdu_session_types"]:
        types = ", ".join(f"{k}×{v}" for k, v in summary["pdu_session_types"].items())
        lines.append(f"- PDU session types: {types}")
    return "\n".join(lines)
