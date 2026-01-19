"""
Telecom PCAP Analyzer - FastAPI Backend
Simple POC implementation for 5G protocol analysis with LLM enrichment
"""
import os
import uuid
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import shutil
import json

from .pcap_parser import parse_pcap
from .telecom_analyzer import analyze_flows, get_protocol_stats, get_technology_stats, identify_telecom_sessions, correlate_sessions, extract_message_sequence, get_failure_summary, format_session_for_export
from .llm_service import enrich_with_llm, root_cause_analysis
from decode.tshark import tshark_available, get_tshark_stats

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
UPLOAD_DIR = Path(__file__).parent.parent / "uploads"
ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", 500)) * 1024 * 1024  # Convert to bytes

# In-memory storage for POC
analyses: Dict[str, Dict[str, Any]] = {}
active_websockets: Dict[str, WebSocket] = {}


def infer_capture_point(protocols: list) -> dict:
    """
    Infer where the capture was taken based on observed protocol mix.
    This helps LLM avoid false conclusions about missing protocols.
    """
    protocols_set = set(p.upper() for p in protocols)
    
    # 5G Core / UPF
    if "PFCP" in protocols_set:
        return {
            "point": "5G_CORE_UPF",
            "description": "5G User Plane Function or SMF interface",
            "expected": ["PFCP", "GTP-U"],
            "not_expected": ["RTP", "SIP", "NGAP"],
        }
    
    # 5G RAN-Core Interface
    if "NGAP" in protocols_set:
        return {
            "point": "5G_RAN_CORE",
            "description": "gNB to AMF/UPF interface",
            "expected": ["NGAP", "NAS-5GS", "GTP-U"],
            "not_expected": ["RTP", "SIP", "Diameter"],
        }
    
    # 4G RAN-Core Interface
    if "S1AP" in protocols_set:
        return {
            "point": "4G_RAN_CORE",
            "description": "eNB to MME/SGW interface",
            "expected": ["S1AP", "NAS-EMM", "GTP-U"],
            "not_expected": ["RTP", "SIP"],
        }
    
    # IMS/VoLTE Core
    if "SIP" in protocols_set and "RTP" in protocols_set:
        return {
            "point": "IMS_CORE",
            "description": "IMS Core (P-CSCF/S-CSCF) with media",
            "expected": ["SIP", "RTP", "Diameter"],
            "not_expected": ["NGAP", "S1AP", "PFCP"],
        }
    
    # Signaling-only SIP (no media)
    if "SIP" in protocols_set and "RTP" not in protocols_set:
        return {
            "point": "IMS_SIGNALING",
            "description": "IMS signaling plane only (no media captured)",
            "expected": ["SIP", "Diameter"],
            "not_expected": ["RTP", "RTCP"],
        }
    
    # EPC Core
    if "GTPV2-C" in protocols_set or "GTP" in protocols_set:
        return {
            "point": "EPC_CORE",
            "description": "EPC Core (MME/SGW/PGW interfaces)",
            "expected": ["GTPv2-C", "GTP-U", "Diameter"],
            "not_expected": ["RTP", "SIP"],
        }
    
    # User plane only
    if "GTP-U" in protocols_set:
        return {
            "point": "USER_PLANE",
            "description": "User plane transport only",
            "expected": ["GTP-U", "IP"],
            "not_expected": ["GTPv2-C", "PFCP", "SIP"],
        }
    
    return {
        "point": "UNKNOWN",
        "description": "Capture point could not be determined",
        "expected": [],
        "not_expected": [],
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Upload directory: {UPLOAD_DIR}")
    logger.info("PCAP Analyzer backend started")
    yield
    # Shutdown
    logger.info("PCAP Analyzer backend shutting down")


# Create FastAPI app
app = FastAPI(
    title="NetTrace AI",
    description="Intelligent Mobile Network Analysis - Advanced PCAP analyzer for 2G/3G/4G/5G protocols with AI-powered insights",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for frontend (permissive for POC)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for POC
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def broadcast_progress(job_id: str, progress: int, message: str, stage: str = "processing"):
    """Send progress update via WebSocket"""
    if job_id in active_websockets:
        try:
            await active_websockets[job_id].send_json({
                "progress": progress,
                "message": message,
                "stage": stage
            })
        except Exception as e:
            logger.warning(f"Failed to send WebSocket update: {e}")


async def analyze_pcap_task(job_id: str, file_path: str, filename: str):
    """
    Async task to analyze PCAP file
    """
    try:
        # Stage 1: Parse PCAP
        analyses[job_id]["progress"] = 10
        analyses[job_id]["stage"] = "parsing"
        await broadcast_progress(job_id, 10, "Parsing PCAP file...", "parsing")
        
        packets = await asyncio.to_thread(parse_pcap, file_path)
        
        if not packets:
            raise ValueError("No packets found in PCAP file")
        
        analyses[job_id]["progress"] = 30
        await broadcast_progress(job_id, 30, f"Parsed {len(packets)} packets", "parsing")
        await asyncio.sleep(0.8)  # UX pacing
        
        # Stage 2: Analyze flows
        analyses[job_id]["progress"] = 40
        analyses[job_id]["stage"] = "analyzing"
        await broadcast_progress(job_id, 40, "Analyzing network flows...", "analyzing")
        
        flows = await asyncio.to_thread(analyze_flows, packets)
        protocol_stats = await asyncio.to_thread(get_protocol_stats, flows)
        technology_stats = await asyncio.to_thread(get_technology_stats, flows)
        sessions = await asyncio.to_thread(identify_telecom_sessions, flows)
        sessions = await asyncio.to_thread(identify_telecom_sessions, flows)
        correlated = await asyncio.to_thread(correlate_sessions, flows)
        failure_summary = await asyncio.to_thread(get_failure_summary, flows)
        message_sequence = await asyncio.to_thread(extract_message_sequence, packets, max_messages=100)
        
        analyses[job_id]["progress"] = 60
        await broadcast_progress(job_id, 60, f"Identified {len(flows)} flows", "analyzing")
        await asyncio.sleep(0.8)  # UX pacing
        
        # Stage 3: LLM Enrichment
        analyses[job_id]["progress"] = 70
        analyses[job_id]["stage"] = "enriching"
        await broadcast_progress(job_id, 70, "Enriching with AI insights...", "enriching")
        
        enriched_flows = await enrich_with_llm(flows)
        
        analyses[job_id]["progress"] = 85
        await broadcast_progress(job_id, 85, "Performing deep root cause analysis...", "enriching")
        await asyncio.sleep(0.5)  # UX pacing
        
        # Stage 4: Root Cause Analysis
        summary = {
            "total_flows": len(flows),
            "total_packets": len(packets),
            "total_bytes": sum(f.get("total_bytes", 0) for f in flows),
            "protocols": list(protocol_stats.keys()),
            "capture_point": infer_capture_point(list(protocol_stats.keys())),
        }
        

        
        
        # RCA is now performed later with full TShark context (see line 534+)
        # Placeholder for early failure detection if needed before TShark analysis
        rca = None  # Will be populated by enhanced RCA later
        
        # Calculate capture duration
        if packets:
            timestamps = [p.get("timestamp", 0) for p in packets if p.get("timestamp")]
            if timestamps:
                summary["duration"] = max(timestamps) - min(timestamps)
                summary["start_time"] = min(timestamps)
                summary["end_time"] = max(timestamps)
        
        # Optional: TShark Analysis (3-Mode Strategy)
        tshark_stats = {}
        tshark_transactions = []
        
        if tshark_available():
            await broadcast_progress(job_id, 90, "Running deep protocol analysis...", "enriching")
            
            # Mode A: Stats & Analytics
            try:
                tshark_stats = await asyncio.to_thread(get_tshark_stats, file_path)
            except Exception as e:
                logger.warning(f"TShark stats failed: {e}")

            # Mode B: Field-Based Decode & Transaction Building
            try:
                from decode.tshark import extract_telecom_fields
                from decode.transactions_builder import build_transactions
                from analytics.kpi_engine import calculate_procedure_kpis, compare_time_windows
                from analytics.temporal_analysis import analyze_temporal_patterns, format_for_llm
                from analytics.subscriber_tracker import analyze_subscriber_journeys, format_for_llm as format_subscriber_llm
                
                # Extract raw fields
                field_data = await asyncio.to_thread(extract_telecom_fields, file_path)
                logger.info(f"Extracted {len(field_data)} packets with TShark")
                
                # Build structured transactions
                tshark_transactions = await asyncio.to_thread(build_transactions, field_data)
                
                # Calculate Analytics
                procedure_kpis = await asyncio.to_thread(calculate_procedure_kpis, tshark_transactions)
                time_window_diffs = await asyncio.to_thread(compare_time_windows, tshark_transactions)
                
                # Temporal Anomaly Detection
                temporal_results = await asyncio.to_thread(analyze_temporal_patterns, tshark_transactions)
                temporal_llm_context = format_for_llm(temporal_results)
                logger.info(f"Temporal analysis: {temporal_results['summary']['total_anomalies']} anomalies detected")
                
                # Subscriber Correlation
                subscriber_data = await asyncio.to_thread(analyze_subscriber_journeys, tshark_transactions)
                subscriber_llm_context = format_subscriber_llm(subscriber_data)
                logger.info(f"Subscriber analysis: {subscriber_data.get('subscriber_count', 0)} subscribers identified")
                
            except Exception as e:
                logger.warning(f"TShark transaction build failed: {e}")
                procedure_kpis = {}
                time_window_diffs = {}
                temporal_results = {}
                temporal_llm_context = ""
                subscriber_data = {}
                subscriber_llm_context = ""
        
            # --- New Voice/IMS Analysis Integration ---
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
                
                # 1. Build Calls
                call_builder = CallBuilder()
                ims_data = await asyncio.to_thread(call_builder.process_transactions, tshark_transactions)
                
                voice_calls = ims_data["calls"]
                registrations = ims_data["registrations"]
                trace_type = ims_data["trace_type"]
                
                # 2. Parse SDP (Only if we have calls? Or could REGISTRATION have SDP? Unlikely, but safe to run)
                sdp_parser = SdpParser()
                call_media = await asyncio.to_thread(sdp_parser.extract_from_transactions, tshark_transactions)
                
                # 3. Map Media (Only if calls exist)
                media_mapper = MediaMapper()
                if voice_calls:
                     media_streams = await asyncio.to_thread(media_mapper.map_streams_to_calls, voice_calls, call_media, flows)
                else:
                     media_streams = []
                
                # 4. Detect Issues
                media_findings_engine = MediaFindings()
                media_findings = await asyncio.to_thread(media_findings_engine.analyze_streams, media_streams, voice_calls)
                
                # 5. NEW: Codec Mismatch Detection
                codec_analyzer = CodecAnalyzer()
                codec_findings = await asyncio.to_thread(codec_analyzer.analyze_call_codecs, call_media)
                codec_llm_context = format_codec_context_for_llm(codec_findings, call_media)
                
                # 6. NEW: Precondition Analysis
                precondition_analyzer = PreconditionAnalyzer()
                precondition_findings = await asyncio.to_thread(
                    precondition_analyzer.detect_precondition_issues, voice_calls, tshark_transactions
                )
                precondition_llm_context = format_precondition_context_for_llm(precondition_findings)
                
                # 7. NEW: Ringback Diagnosis
                ringback_analyzer = RingbackAnalyzer()
                # Get media presence for ringback analysis
                from analysis.rtp_detector import RtpPresenceDetector
                rtp_detector = RtpPresenceDetector()
                media_presence = await asyncio.to_thread(rtp_detector.detect_presence, call_media, flows)
                ringback_findings = await asyncio.to_thread(
                    ringback_analyzer.detect_ringback_issues, voice_calls, tshark_transactions, media_presence
                )
                ringback_llm_context = format_ringback_context_for_llm(ringback_findings)
                
                # 8. NEW: RTP Quality Analysis (if RTP captured)
                rtp_quality_results = []
                rtp_quality_llm_context = ""
                # Extract RTP packets from field_data
                rtp_packets = [p for p in field_data if p.get("rtp.seq")]
                if rtp_packets:
                    rtp_analyzer = RtpQualityAnalyzer()
                    for call in voice_calls[:5]:  # Limit to first 5 calls
                        call_id = call.get("call_id")
                        # Filter RTP by call's expected ports (simplified - would need port matching)
                        quality = rtp_analyzer.analyze_call_streams(call_id, rtp_packets[:100], [])
                        rtp_quality_results.append(quality)
                    rtp_quality_llm_context = format_rtp_quality_for_llm(rtp_quality_results)
                
                # 9. Session Timer Context
                session_timer_context = ""
                calls_with_timer = [c for c in voice_calls if c.get("session_timer", {}).get("session_expires")]
                if calls_with_timer:
                    timer_lines = ["## SESSION TIMER (RFC 4028)"]
                    for c in calls_with_timer[:5]:
                        st = c["session_timer"]
                        timer_lines.append(f"- Call {c['call_id'][:8]}: SE={st['session_expires']}s, Refresher={st.get('refresher', 'N/A')}, Expired={st.get('is_expired', False)}")
                    session_timer_context = "\n".join(timer_lines)
                
                # 10. Call Transfer Context
                transfer_context = ""
                calls_with_transfer = [c for c in voice_calls if c.get("transfer", {}).get("is_transfer")]
                if calls_with_transfer:
                    xfer_lines = ["## CALL TRANSFER (RFC 3515)"]
                    for c in calls_with_transfer[:5]:
                        xf = c["transfer"]
                        xfer_lines.append(f"- Call {c['call_id'][:8]}: Refer-To={xf.get('refer_to', 'N/A')}, Status={xf.get('transfer_status', 'N/A')}")
                    transfer_context = "\n".join(xfer_lines)
                
                # 11. NEW: SRVCC/CSFB Handover Detection
                handover_context = ""
                handover_results = {}
                try:
                    # Extract S1AP/NGAP transactions
                    s1ap_txns = [t for t in tshark_transactions if t.get("s1ap.procedureCode")]
                    ngap_txns = [t for t in tshark_transactions if t.get("ngap.procedureCode")]
                    sip_txns = [t for t in tshark_transactions if t.get("sip.Method") or t.get("sip.Status-Code")]
                    
                    handover_results = await asyncio.to_thread(
                        analyze_handover,
                        voice_calls,
                        s1ap_txns,
                        ngap_txns,
                        sip_txns
                    )
                    
                    if handover_results.get("handover_detected"):
                        ho_lines = ["## SRVCC/CSFB DETECTION"]
                        ho_lines.append(f"RAN Evidence Available: {handover_results.get('has_ran_evidence')}")
                        for finding in handover_results.get("findings", []):
                            ho_lines.append(f"- **{finding['classification']}** (Confidence: {finding['confidence_level']} {finding['confidence_pct']}%)")
                            ho_lines.append(f"  - {finding['description']}")
                            ho_lines.append(f"  - Evidence: {', '.join(finding['evidence'][:3])}")
                        handover_context = "\n".join(ho_lines)
                        logger.info(f"Handover Detection: {handover_results.get('summary')}")
                except Exception as e:
                    logger.warning(f"Handover detection failed: {e}")
                
                # Merge all findings into media_findings for frontend
                all_voip_findings = media_findings + codec_findings + precondition_findings + ringback_findings
                
                logger.info(f"IMS Analysis: Type={trace_type}, Calls={len(voice_calls)}, Regs={len(registrations)}")
                logger.info(f"VoLTE Findings: Codec={len(codec_findings)}, Precond={len(precondition_findings)}, Ringback={len(ringback_findings)}")
                
            except Exception as e:
                logger.error(f"Voice Analysis failed: {e}")
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
            
        # Prepare Artifacts
        artifact_path = ARTIFACTS_DIR / job_id
        artifact_path.mkdir(parents=True, exist_ok=True)
        
        # Save Voice Artifacts
        with open(artifact_path / "calls.json", "w") as f:
            json.dump(voice_calls, f, indent=2, default=str)
        
        with open(artifact_path / "registrations.json", "w") as f:
            json.dump(registrations, f, indent=2, default=str)
            
        with open(artifact_path / "media_streams.json", "w") as f:
             json.dump(media_streams, f, indent=2, default=str)
             
        with open(artifact_path / "media_findings.json", "w") as f:
            json.dump(media_findings, f, indent=2)

        # 1. Summary.json
        with open(artifact_path / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)
            
        # 2. Flows.json
        with open(artifact_path / "flows.json", "w") as f:
            # Clean flows for JSON (remove sets if any remain, though analyze_flows cleans up)
            json.dump(flows, f, indent=2, default=str)
            
        # 3. Sessions.json (Formatted)
        formatted_sessions = [format_session_for_export(s) for s in sessions]
        with open(artifact_path / "sessions.json", "w") as f:
            json.dump(formatted_sessions, f, indent=2, default=str)
            
        # 4. Transactions.json (Enriched)
        # Combine Scapy message sequence and TShark structured transactions
        transactions_artifact = {
             "scapy_sequence": message_sequence,
             "deep_transactions": tshark_transactions,
             "voice_analysis": {
                 "trace_type": trace_type,
                 "calls": voice_calls,
                 "registrations": registrations,
                 "findings": media_findings
             }
        }
        with open(artifact_path / "transactions.json", "w") as f:
             json.dump(transactions_artifact, f, indent=2, default=str)
             
        # 5. Expert Findings (TShark Mode A)
        expert_findings = tshark_stats.get("expert_info", [])
        if media_findings:
            # Merge Voice Media Findings into Expert Findings for frontend visibility
             for mf in media_findings:
                 expert_findings.append({
                     "severity": "Warning" if mf["severity"] == "warning" else "Error",
                     "group": "Voice Quality",
                     "protocol": "VoIP",
                     "summary": mf["title"] + ": " + mf["description"]
                 })
                 
        with open(artifact_path / "expert_findings.json", "w") as f:
            json.dump(expert_findings, f, indent=2)
            
        # 6. Analytics KPIs
        analytics_artifact = {
            "procedure_kpis": procedure_kpis,
            "time_window_diffs": time_window_diffs,
            "sctp_stats": tshark_stats.get("sctp_stats"), # Raw text or parsed
            "voice_stats": {
                "trace_type": trace_type,
                "total_calls": len(voice_calls),
                "total_registrations": len(registrations),
                "dropped": len([c for c in voice_calls if "DROP" in str(c.get("end_reason", ""))]),
                "media_issues": len(media_findings)
            }
        }
        with open(artifact_path / "analysis_kpis.json", "w") as f:
            json.dump(analytics_artifact, f, indent=2)
             
        # 7. Findings.json (RCA)
        # Update RCA call to include new context
        # We need to re-run RCA here or ensure it was run with this data?
        # The original code flow had RCA run via `llm_service.root_cause_analysis` BEFORE this block?
        # No, RCA was run via `analyze_flows`? No, let's check.
        # Wait, the `rca` variable is used in line 218 in original code. 
        # Where does `rca` come from? It was computed earlier using Scapy data!
        # We need to RE-RUN or ENHANCE the RCA with the new TShark data.
        
        # NOTE: In previous steps, we updated `root_cause_analysis` to accept `expert_findings` and `transactions`.
        # But we called it `analyze_flows` -> `root_cause_analysis`.
        # We should probably call `root_cause_analysis` DIRECTLY here with the full context.
        
        # Let's perform a SECOND pass or simply call it here if it wasn't called yet?
        # Looking at previous file views, `analyze_flows` calls `root_cause_analysis`.
        # We should probably call `root_cause_analysis` DIRECTLY here with the full context.
        
        # Re-calc RCA with full context
        # Re-calc RCA with full context
        
        # Prepare Voice Context for LLM
        voice_context = {
            "calls": voice_calls[:10], # Top 10 calls
            "media_findings": all_voip_findings if 'all_voip_findings' in dir() else media_findings,
            "stats": analytics_artifact["voice_stats"]
        }
        
        # Generate Vendor Code Context for LLM
        vendor_context = ""
        try:
            from decode.vendor_codes import load_vendor_mappings, format_vendor_reason_for_display
            from decode.transactions_builder import parse_reason_header
            
            vendor_mappings = load_vendor_mappings()
            
            # Build vendor context from observed reason headers
            vendor_lines = ["## VENDOR CODE MAPPINGS"]
            vendor_lines.append("The following vendor-specific codes are mapped:")
            vendor_lines.append("")
            vendor_lines.append("### Nokia MSS (X.int format)")
            x_int_codes = vendor_mappings.get("X.int", {}).get("codes", {})
            for code, label in x_int_codes.items():
                vendor_lines.append(f"- `{code}`: **{label}**")
            
            vendor_lines.append("")
            vendor_lines.append("### Huawei IMS (proprietary text patterns)")
            huawei_patterns = vendor_mappings.get("huawei_text_patterns", {})
            for pattern, info in huawei_patterns.items():
                if not pattern.startswith("_"):
                    vendor_lines.append(f"- `{pattern}`: {info.get('component', 'Unknown')} - {info.get('meaning', 'Unknown')}")
            
            vendor_lines.append("")
            vendor_lines.append("**IMPORTANT**: When you see `X.int;reasoncode=0x00000000`, map it to 'Normal clearing' (Nokia MSS).")
            vendor_lines.append("When you see `X.int;reasoncode=0x00000603`, map it to 'Call release' (Nokia MSS).")
            
            vendor_context = "\n".join(vendor_lines)
            logger.info("Generated vendor code context for LLM")
        except Exception as e:
            logger.warning(f"Failed to generate vendor context: {e}")
        
        rca = await root_cause_analysis(
            flows=enriched_flows,
            summary=summary,
            correlated_sessions=sessions,
            failure_summary=failure_summary,
            expert_findings=expert_findings,
            transactions=tshark_transactions,
            procedure_kpis=procedure_kpis,
            voice_context=voice_context,
            temporal_context=temporal_llm_context,
            subscriber_context=subscriber_llm_context,
            # New VoLTE enhancement contexts
            codec_context=codec_llm_context if 'codec_llm_context' in dir() else None,
            ringback_context=ringback_llm_context if 'ringback_llm_context' in dir() else None,
            precondition_context=precondition_llm_context if 'precondition_llm_context' in dir() else None,
            rtp_quality_context=rtp_quality_llm_context if 'rtp_quality_llm_context' in dir() else None,
            session_timer_context=session_timer_context if 'session_timer_context' in dir() else None,
            transfer_context=transfer_context if 'transfer_context' in dir() else None,
            handover_context=handover_context if 'handover_context' in dir() else None,
            vendor_context=vendor_context if vendor_context else None
        )

        with open(artifact_path / "findings.json", "w") as f:
            json.dump(rca, f, indent=2)
            
        logger.info(f"Artifacts saved to {artifact_path}")

        
        # Store results
        results = {
            "flows": enriched_flows,
            "root_cause_analysis": rca,
            "summary": summary,
            "protocol_stats": protocol_stats,
            "technology_stats": technology_stats,
            "telecom_sessions": sessions,
            "message_sequence": message_sequence,
            "voice_analysis": {
                "calls": voice_calls,
                "findings": media_findings,
                "stats": analytics_artifact["voice_stats"]
            }
        }
        
        analyses[job_id]["status"] = "completed"
        analyses[job_id]["progress"] = 100
        analyses[job_id]["results"] = results
        analyses[job_id]["stage"] = "completed"
        
        await broadcast_progress(job_id, 100, "Analysis complete!", "completed")
        logger.info(f"Analysis completed for job {job_id}")
        
    except Exception as e:
        logger.error(f"Analysis failed for job {job_id}: {e}")
        analyses[job_id]["status"] = "failed"
        analyses[job_id]["error"] = str(e)
        analyses[job_id]["stage"] = "failed"
        await broadcast_progress(job_id, 0, f"Error: {str(e)}", "failed")
    
    finally:
        # Clean up uploaded file after analysis (optional for POC)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Cleaned up file: {file_path}")
        except Exception as e:
            logger.warning(f"Failed to clean up file: {e}")


from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

# ... (Previous imports stay, I need to be careful with replace_file_content)

# Mount static files (Frontend)
# We need to ensure the build directory exists or handle it gracefully
BUILD_DIR = Path(__file__).parent.parent.parent / "frontend" / "build"

if (BUILD_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=BUILD_DIR / "static"), name="static")




@app.get("/api/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "active_analyses": len(analyses),
        "upload_dir": str(UPLOAD_DIR),
        "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024)
    }


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Upload a PCAP file for analysis
    
    Returns job_id for tracking progress
    """
    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file type. Only .pcap and .pcapng files are supported"
        )
    
    # Read file content
    content = await file.read()
    
    # Validate file size
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)} MB"
        )
    
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    
    # Generate job ID and save file
    job_id = str(uuid.uuid4())
    safe_filename = f"{job_id}_{file.filename.replace(' ', '_')}"
    file_path = UPLOAD_DIR / safe_filename
    
    try:
        file_path.write_bytes(content)
        logger.info(f"Saved file: {file_path} ({len(content)} bytes)")
    except Exception as e:
        logger.error(f"Failed to save file: {e}")
        raise HTTPException(status_code=500, detail="Failed to save uploaded file")
    
    # Initialize analysis job
    analyses[job_id] = {
        "job_id": job_id,
        "status": "processing",
        "progress": 0,
        "stage": "uploading",
        "filename": file.filename,
        "file_size": len(content),
        "results": None,
        "error": None
    }
    
    # Start async analysis
    asyncio.create_task(analyze_pcap_task(job_id, str(file_path), file.filename))
    
    return {"job_id": job_id, "filename": file.filename, "size": len(content)}


@app.get("/api/analysis/{job_id}")
async def get_analysis(job_id: str):
    """
    Get analysis status and results
    """
    if job_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    
    return analyses[job_id]


@app.get("/api/flows/{job_id}")
async def get_flows(job_id: str, limit: int = 100, offset: int = 0):
    """
    Get flows from analysis with pagination
    """
    if job_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    
    analysis = analyses[job_id]
    
    if analysis["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis not completed yet")
    
    flows = analysis["results"]["flows"]
    total = len(flows)
    
    return {
        "flows": flows[offset:offset + limit],
        "total": total,
        "offset": offset,
        "limit": limit
    }


@app.websocket("/ws/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: str):
    """
    WebSocket endpoint for real-time progress updates
    """
    await websocket.accept()
    active_websockets[job_id] = websocket
    logger.info(f"WebSocket connected for job {job_id}")
    
    try:
        # Send current status if analysis exists
        if job_id in analyses:
            await websocket.send_json({
                "progress": analyses[job_id]["progress"],
                "message": f"Status: {analyses[job_id]['status']}",
                "stage": analyses[job_id].get("stage", "unknown")
            })
        
        # Keep connection alive
        while True:
            try:
                # Wait for messages (ping/pong or close)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                # Echo back or handle commands
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Send keepalive
                try:
                    await websocket.send_json({"type": "keepalive"})
                except:
                    break
                    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for job {job_id}")
    except Exception as e:
        logger.warning(f"WebSocket error for job {job_id}: {e}")
    finally:
        if job_id in active_websockets:
            del active_websockets[job_id]


@app.delete("/api/analysis/{job_id}")
async def delete_analysis(job_id: str):
    """
    Delete an analysis job and its results
    """
    if job_id not in analyses:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    
    del analyses[job_id]
    logger.info(f"Deleted analysis job {job_id}")
    
    return {"status": "deleted", "job_id": job_id}

@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    """Serve the React application"""
    # Exclude API routes from this catch-all (though FastAPI should handle specific routes first)
    if full_path.startswith("api") or full_path.startswith("ws"):
        raise HTTPException(status_code=404, detail="Not found")
        
    file_path = BUILD_DIR / full_path
    if file_path.exists() and file_path.is_file():
        return FileResponse(file_path)
    
    return FileResponse(BUILD_DIR / "index.html")



# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
