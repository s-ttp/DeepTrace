"""Run the existing Phase 2 analysers against pre-parsed Huawei IMS transactions.

The Huawei trace gives us a structured transaction list directly (no TShark
needed), so this is a lighter-weight orchestrator than ``advanced_pcap_pipeline``.
It returns a ``pcap_results``-shaped dict so the case-based analyser in
``main.py`` can call ``root_cause_analysis`` exactly as for a PCAP.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def _failure_summary(transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
    failures = []
    for tx in transactions:
        if str(tx.get("status", "")).lower() == "failure":
            failures.append({
                "protocol": tx.get("protocol"),
                "message_type": tx.get("message_type"),
                "interface": tx.get("interface_family"),
                "code": tx.get("sip.Status-Code") or tx.get("diameter.Result-Code"),
                "src_ne": tx.get("src_ne"),
                "dst_ne": tx.get("dst_ne"),
                "time": tx.get("time_text"),
            })
    return {"failures": failures[:50], "total_failures": len(failures)}


def _procedure_kpis(transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute simple per-procedure success/failure counts."""
    by_proc: Dict[str, Dict[str, int]] = {}
    for tx in transactions:
        proc = tx.get("procedure") or tx.get("message_type") or "UNKNOWN"
        slot = by_proc.setdefault(proc, {"attempts": 0, "success": 0, "failure": 0})
        slot["attempts"] += 1
        status = str(tx.get("status", "")).lower()
        if status == "success":
            slot["success"] += 1
        elif status == "failure":
            slot["failure"] += 1
    return {"procedures": by_proc}


async def run_huawei_pipeline(transactions: List[Dict[str, Any]],
                              huawei_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Run Phase 2 analysers on Huawei IMS transactions.

    Each analyser is wrapped in its own try/except so a single failure cannot
    break the upstream pipeline (mirrors ``advanced_pcap_pipeline.py``).
    """
    diameter_app_context = ""
    subscriber_llm_context = ""
    subscriber_journey_context = ""
    trend_context = ""
    voice_context = None
    pfcp_context = ""
    sbi_context = ""

    try:
        from analytics.subscriber_tracker import analyze_subscriber_journeys, format_for_llm as format_subscriber_llm
        sub = await asyncio.to_thread(analyze_subscriber_journeys, transactions)
        subscriber_llm_context = format_subscriber_llm(sub)
        subscriber_journey_context = sub.get("journey_context_for_llm", "") if isinstance(sub, dict) else ""
    except Exception as e:
        logger.warning("Huawei pipeline: subscriber analysis failed: %s", e)

    try:
        from analysis.diameter_analyzer import analyze_diameter, format_diameter_context_for_llm
        d_summary = await asyncio.to_thread(analyze_diameter, transactions)
        diameter_app_context = format_diameter_context_for_llm(d_summary)
    except Exception as e:
        logger.warning("Huawei pipeline: Diameter analysis failed: %s", e)

    try:
        from analytics.trend_detector import detect_trends, format_trends_for_llm
        t = await asyncio.to_thread(detect_trends, transactions)
        trend_context = format_trends_for_llm(t)
    except Exception as e:
        logger.warning("Huawei pipeline: trend detection failed: %s", e)

    # Voice/IMS reconstruction. Reuse the same CallBuilder + SdpParser /
    # MediaFindings the PCAP pipeline uses — our Huawei transactions have the
    # same SIP-shaped fields (protocol, message_type, session_ids.call_id,
    # sip.From/To/CSeq/...).
    voice_calls: List[Dict[str, Any]] = []
    registrations: List[Dict[str, Any]] = []
    media_findings: List[Dict[str, Any]] = []
    media_streams: List[Dict[str, Any]] = []
    voice_stats: Dict[str, Any] = {}
    voice_trace_type = "UNKNOWN"
    try:
        from analysis.call_builder import CallBuilder
        from analysis.sdp_parser import SdpParser
        from analysis.media_mapper import MediaMapper
        from analysis.media_findings import MediaFindings

        cb = CallBuilder()
        ims_data = await asyncio.to_thread(cb.process_transactions, transactions)
        voice_calls = ims_data.get("calls", [])
        registrations = ims_data.get("registrations", [])
        voice_trace_type = ims_data.get("trace_type", "UNKNOWN")
        voice_stats = ims_data.get("sip_kpis", {}) or {}

        try:
            sp = SdpParser()
            call_media = await asyncio.to_thread(sp.extract_from_transactions, transactions)
            mm = MediaMapper()
            media_streams = await asyncio.to_thread(mm.map_streams_to_calls, voice_calls, call_media, [])
            mf = MediaFindings()
            media_findings = await asyncio.to_thread(mf.analyze_streams, media_streams, voice_calls)
        except Exception as e:
            logger.debug("Huawei pipeline: SDP/media inner step skipped: %s", e)

        voice_context = {
            "trace_type": voice_trace_type,
            "calls": voice_calls,
            "media_findings": media_findings,
            "stats": voice_stats,
        }
    except Exception as e:
        logger.warning("Huawei pipeline: voice reconstruction failed: %s", e)
        voice_context = None

    # Build a synthetic "flows" view from src/dst node pairs to satisfy the
    # downstream summary keys without lying about packet counts.
    flows = []
    seen_pairs = set()
    for tx in transactions:
        key = (tx.get("src_ip"), tx.get("dst_ip"), tx.get("protocol"))
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        flows.append({
            "src_ip": tx.get("src_ip"),
            "dst_ip": tx.get("dst_ip"),
            "src_port": tx.get("src_port"),
            "dst_port": tx.get("dst_port"),
            "protocol": tx.get("protocol"),
            "transport": "SCTP" if "SCTP" in (tx.get("sip.Via") or "") else "UDP",
            "packet_count": 0,
            "total_bytes": 0,
            "primary_tech": "IMS",
        })

    duration = huawei_summary.get("time_range", {}).get("duration_seconds") or 0
    summary = {
        "total_flows": len(flows),
        "total_packets": len(transactions),
        "total_bytes": 0,
        "duration": duration,
        "protocols": sorted({tx.get("protocol", "Unknown") for tx in transactions}),
        "capture_point": {
            "point": "IMS_CORE",
            "description": "Huawei IMS core trace (CSCF / HSS / ATS / ENS / SCP / Cloud SE)",
            "expected": ["SIP", "Diameter"],
            "not_expected": ["S1AP", "NGAP", "PFCP", "RTP"],
        },
    }

    # Pre-build the message_sequence (for FlowDiagram) and a deterministic
    # Mermaid diagram (overrides the LLM's hallucinated happy-path).
    try:
        from .huawei_html import build_message_sequence, build_mermaid_diagram
        message_sequence = build_message_sequence(transactions, max_messages=60)
        sequence_diagram_mermaid = build_mermaid_diagram(transactions, max_steps=40)
    except Exception as e:
        logger.warning("Huawei pipeline: diagram build failed: %s", e)
        message_sequence = []
        sequence_diagram_mermaid = ""

    return {
        "flows": flows,
        "summary": summary,
        "transactions": transactions,
        "message_sequence": message_sequence,
        "sequence_diagram_override": sequence_diagram_mermaid,
        "failure_summary": _failure_summary(transactions),
        "expert_findings": [],
        "procedure_kpis": _procedure_kpis(transactions),
        "voice_context": voice_context,
        "voice_calls": voice_calls,
        "registrations": registrations,
        "media_findings": media_findings,
        "media_streams": media_streams,
        "temporal_context": "",
        "subscriber_context": subscriber_llm_context,
        "subscriber_journey_context": subscriber_journey_context,
        "diameter_app_context": diameter_app_context,
        "trend_context": trend_context,
        "pfcp_context": pfcp_context,
        "sbi_context": sbi_context,
        "vendor_context": "",
        "ran_context": "",
        "codec_context": "",
        "ringback_context": "",
        "precondition_context": "",
        "rtp_quality_context": "",
        "session_timer_context": "",
        "transfer_context": "",
        "handover_context": "",
        "slicing_context": "",
        "ho_quality_context": "",
        "huawei_summary": huawei_summary,
    }
