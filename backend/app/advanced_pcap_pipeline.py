import asyncio
import logging
import json
from decode.tshark import tshark_available

logger = logging.getLogger(__name__)

async def run_advanced_pipeline(file_path, flows, packets, broadcast_cb=None):
    from .main import get_tshark_stats, extract_message_sequence
    
    tshark_stats = {}
    tshark_transactions = []
    advanced_context = {}
    
    # Initialize default contexts
    voice_context = None
    procedure_kpis = {}
    time_window_diffs = {}
    temporal_llm_context = ""
    subscriber_llm_context = ""
    node_map = {}
    voice_calls = []
    registrations = []
    media_streams = []
    media_findings = []
    all_voip_findings = []
    trace_type = "UNKNOWN"
    codec_llm_context = ""
    precondition_llm_context = ""
    ringback_llm_context = ""
    rtp_quality_llm_context = ""
    session_timer_context = ""
    transfer_context = ""
    handover_context = ""
    expert_findings = []
    ran_context = ""
    vendor_context = ""

    if tshark_available():
        if broadcast_cb:
            await broadcast_cb("Running deep protocol analysis...", "enriching")
        
        # Mode A: Stats
        try:
            tshark_stats = await asyncio.to_thread(get_tshark_stats, file_path)
        except Exception as e:
            logger.warning(f"TShark stats failed: {e}")

        # Mode B: Field-Based Decode
        try:
            from decode.tshark import extract_telecom_fields
            from decode.transactions_builder import build_transactions
            from analytics.kpi_engine import calculate_procedure_kpis, compare_time_windows
            from analytics.temporal_analysis import analyze_temporal_patterns, format_for_llm
            from analytics.subscriber_tracker import analyze_subscriber_journeys, format_for_llm as format_subscriber_llm
            
            field_data = await asyncio.to_thread(extract_telecom_fields, file_path)
            tshark_transactions = await asyncio.to_thread(build_transactions, field_data)
            logger.info(f"ADVANCED PIPELINE DEBUG: Built {len(tshark_transactions)} transactions from {len(field_data)} fields.")
            
            procedure_kpis = await asyncio.to_thread(calculate_procedure_kpis, tshark_transactions)
            time_window_diffs = await asyncio.to_thread(compare_time_windows, tshark_transactions)
            
            temporal_results = await asyncio.to_thread(analyze_temporal_patterns, tshark_transactions)
            temporal_llm_context = format_for_llm(temporal_results)
            
            subscriber_data = await asyncio.to_thread(analyze_subscriber_journeys, tshark_transactions)
            subscriber_llm_context = format_subscriber_llm(subscriber_data)
            
            from .node_classifier import classify_network_nodes
            node_map = await classify_network_nodes(tshark_transactions)
            
        except Exception as e:
            logger.warning(f"TShark transaction build failed: {e}")

        # --- Voice/IMS Analysis ---
        try:
            from analysis.call_builder import CallBuilder
            from analysis.sdp_parser import SdpParser
            from analysis.media_mapper import MediaMapper
            from analysis.media_findings import MediaFindings
            from analysis.codec_analyzer import CodecAnalyzer, format_codec_context_for_llm
            from analysis.precondition_analyzer import PreconditionAnalyzer, format_precondition_context_for_llm
            from analysis.ringback_analyzer import RingbackAnalyzer, format_ringback_context_for_llm
            from analysis.rtp_quality import RtpQualityAnalyzer, format_rtp_quality_for_llm
            from analysis.handover_analyzer import analyze_handover
            
            call_builder = CallBuilder()
            ims_data = await asyncio.to_thread(call_builder.process_transactions, tshark_transactions)
            
            voice_calls = ims_data["calls"]
            registrations = ims_data["registrations"]
            trace_type = ims_data["trace_type"]
            
            sdp_parser = SdpParser()
            call_media = await asyncio.to_thread(sdp_parser.extract_from_transactions, tshark_transactions)
            
            media_mapper = MediaMapper()
            media_streams = await asyncio.to_thread(media_mapper.map_streams_to_calls, voice_calls, call_media, flows)
            
            media_findings_engine = MediaFindings()
            media_findings = await asyncio.to_thread(media_findings_engine.analyze_streams, media_streams, voice_calls)
            
            codec_analyzer = CodecAnalyzer()
            codec_findings = await asyncio.to_thread(codec_analyzer.analyze_call_codecs, call_media)
            codec_llm_context = format_codec_context_for_llm(codec_findings, call_media)
            
            precondition_analyzer = PreconditionAnalyzer()
            precondition_findings = await asyncio.to_thread(
                precondition_analyzer.detect_precondition_issues, voice_calls, tshark_transactions
            )
            precondition_llm_context = format_precondition_context_for_llm(precondition_findings)
            
            ringback_analyzer = RingbackAnalyzer()
            from analysis.rtp_detector import RtpPresenceDetector
            rtp_detector = RtpPresenceDetector()
            media_presence = await asyncio.to_thread(rtp_detector.detect_presence, call_media, flows)
            ringback_findings = await asyncio.to_thread(
                ringback_analyzer.detect_ringback_issues, voice_calls, tshark_transactions, media_presence
            )
            ringback_llm_context = format_ringback_context_for_llm(ringback_findings)
            
            rtp_quality_results = []
            rtp_packets = [p for p in field_data if p.get("rtp.seq")]
            if rtp_packets:
                rtp_analyzer = RtpQualityAnalyzer()
                for call in voice_calls[:5]:
                    quality = rtp_analyzer.analyze_call_streams(call.get("call_id"), rtp_packets[:100], [])
                    rtp_quality_results.append(quality)
                rtp_quality_llm_context = format_rtp_quality_for_llm(rtp_quality_results)
            
            calls_with_timer = [c for c in voice_calls if c.get("session_timer", {}).get("session_expires")]
            if calls_with_timer:
                timer_lines = ["## SESSION TIMER (RFC 4028)"]
                for c in calls_with_timer[:5]:
                    st = c["session_timer"]
                    timer_lines.append(f"- Call {c['call_id'][:8]}: SE={st['session_expires']}s, Refresher={st.get('refresher', 'N/A')}, Expired={st.get('is_expired', False)}")
                session_timer_context = "\n".join(timer_lines)
            
            calls_with_transfer = [c for c in voice_calls if c.get("transfer", {}).get("is_transfer")]
            if calls_with_transfer:
                xfer_lines = ["## CALL TRANSFER (RFC 3515)"]
                for c in calls_with_transfer[:5]:
                    xf = c["transfer"]
                    xfer_lines.append(f"- Call {c['call_id'][:8]}: Refer-To={xf.get('refer_to', 'N/A')}, Status={xf.get('transfer_status', 'N/A')}")
                transfer_context = "\n".join(xfer_lines)
            
            s1ap_txns = [t for t in tshark_transactions if t.get("s1ap.procedureCode")]
            ngap_txns = [t for t in tshark_transactions if t.get("ngap.procedureCode")]
            sip_txns = [t for t in tshark_transactions if t.get("sip.Method") or t.get("sip.Status-Code")]
            
            try:
                handover_results = await asyncio.to_thread(
                    analyze_handover, voice_calls, s1ap_txns, ngap_txns, sip_txns
                )
                if handover_results.get("handover_detected"):
                    ho_lines = ["## SRVCC/CSFB DETECTION"]
                    ho_lines.append(f"RAN Evidence Available: {handover_results.get('has_ran_evidence')}")
                    for finding in handover_results.get("findings", []):
                        ho_lines.append(f"- **{finding['classification']}** (Confidence: {finding['confidence_level']} {finding['confidence_pct']}%)")
                        ho_lines.append(f"  - {finding['description']}")
                        ho_lines.append(f"  - Evidence: {', '.join(finding['evidence'][:3])}")
                    handover_context = "\n".join(ho_lines)
            except Exception as e:
                logger.warning(f"Handover failure: {e}")
                
            all_voip_findings = media_findings + codec_findings + precondition_findings + ringback_findings
            
        except Exception as e:
            logger.error(f"Voice Analysis failed: {e}")

        # RAN Analysis
        try:
            from .ran import analyze_ran
            from .ran.artifacts import format_findings_for_llm
            ran_results = await asyncio.to_thread(analyze_ran, file_path)
            ran_findings = ran_results.get("ran_findings", [])
            ran_coverage_flags = ran_results.get("coverage_flags", {})
            ran_context = format_findings_for_llm(ran_findings, ran_coverage_flags)
            for rf in ran_findings:
                expert_findings.append({
                    "severity": rf.get("severity", "info").title(),
                    "group": "RAN Analysis",
                    "protocol": rf.get("generation", "Unknown"),
                    "summary": f"{rf.get('type')}: {rf.get('description')}"
                })
        except Exception as e:
            logger.warning(f"RAN failed: {e}")

        expert_findings.extend(tshark_stats.get("expert_info", []))
        if media_findings:
             for mf in media_findings:
                 expert_findings.append({
                     "severity": "Warning" if mf["severity"] == "warning" else "Error",
                     "group": "Voice Quality",
                     "protocol": "VoIP",
                     "summary": mf["title"] + ": " + mf["description"]
                 })

        voice_context = {
            "calls": voice_calls[:10],
            "media_findings": all_voip_findings if all_voip_findings else media_findings,
            "stats": {
                 "trace_type": trace_type,
                 "total_calls": len(voice_calls),
                 "total_registrations": len(registrations),
                 "dropped": len([c for c in voice_calls if "DROP" in str(c.get("end_reason", ""))]),
                 "media_issues": len(media_findings)
            }
        }
        
        try:
            from decode.vendor_codes import load_vendor_mappings
            vendor_mappings = load_vendor_mappings()
            vendor_lines = ["## VENDOR CODE MAPPINGS"]
            vendor_lines.append("The following vendor-specific codes are mapped:")
            
            x_int_codes = vendor_mappings.get("X.int", {}).get("codes", {})
            for code, label in x_int_codes.items():
                vendor_lines.append(f"- `{code}`: **{label}**")
                
            huawei_patterns = vendor_mappings.get("huawei_text_patterns", {})
            for pattern, info in huawei_patterns.items():
                if not pattern.startswith("_"):
                    vendor_lines.append(f"- `{pattern}`: {info.get('component', 'Unknown')} - {info.get('meaning', 'Unknown')}")
            vendor_lines.append("**IMPORTANT**: When you see `X.int;reasoncode=0x00000000`, map it to 'Normal clearing' (Nokia MSS).")
            vendor_lines.append("When you see `X.int;reasoncode=0x00000603`, map it to 'Call release' (Nokia MSS).")
            vendor_context = "\n".join(vendor_lines)
        except Exception as e:
            logger.warning(f"Vendor mapping failed: {e}")
            vendor_context = ""

    # Return constructed contexts
    return {
       "expert_findings": expert_findings,
       "transactions": tshark_transactions,
       "procedure_kpis": procedure_kpis,
       "voice_context": voice_context,
       "temporal_context": temporal_llm_context,
       "subscriber_context": subscriber_llm_context,
       "codec_context": codec_llm_context,
       "ringback_context": ringback_llm_context,
       "precondition_context": precondition_llm_context,
       "rtp_quality_context": rtp_quality_llm_context,
       "session_timer_context": session_timer_context,
       "transfer_context": transfer_context,
       "handover_context": handover_context,
       "vendor_context": vendor_context,
       "ran_context": ran_context,
       "voice_calls": voice_calls,
       "registrations": registrations,
       "media_streams": media_streams,
       "media_findings": media_findings,
       "tshark_stats": tshark_stats,
    }
