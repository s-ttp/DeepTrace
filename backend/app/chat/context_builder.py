"""
Context builder for trace-aware chatbot.
Builds compact context from analysis results for LLM grounding.
"""
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def build_trace_context(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a compact context pack from analysis results.
    
    This extracts only the essential information needed for grounded responses,
    keeping the context size manageable for the LLM.
    
    Args:
        analysis_results: The full results dict from analyses[job_id]
        
    Returns:
        Compact context dict suitable for LLM prompt
    """
    results = analysis_results.get("results", {})
    
    if not results:
        return {
            "status": "no_results",
            "message": "Analysis results not available"
        }
    
    # Extract summary
    summary = results.get("summary", {})
    
    # Extract RCA
    rca = results.get("root_cause_analysis", {})
    
    # Extract flows (top 20 only)
    flows = results.get("flows", [])[:20]
    compact_flows = []
    for i, flow in enumerate(flows):
        compact_flows.append({
            "index": i + 1,
            "protocol": flow.get("protocol", "Unknown"),
            "tech": flow.get("primary_tech", "Unknown"),
            "src": f"{flow.get('src_ip', '?')}:{flow.get('src_port', '?')}",
            "dst": f"{flow.get('dst_ip', '?')}:{flow.get('dst_port', '?')}",
            "packets": flow.get("packet_count", 0),
            "bytes": flow.get("total_bytes", 0),
            "is_gtp": flow.get("is_gtp", False),
            "is_diameter": flow.get("is_diameter", False),
        })
    
    # Extract voice analysis
    voice = results.get("voice_analysis", {})
    voice_stats = voice.get("stats", {})
    voice_findings = voice.get("findings", [])[:10]
    
    # Build context
    context = {
        # Capture overview
        "capture_summary": {
            "total_packets": summary.get("total_packets", 0),
            "total_flows": summary.get("total_flows", 0),
            "total_bytes": summary.get("total_bytes", 0),
            "duration_seconds": summary.get("duration", 0),
            "observed_protocols": summary.get("protocols", []),
        },
        
        # Capture point inference
        "capture_point": summary.get("capture_point", {}),
        
        # Coverage flags (what is/isn't observable)
        "coverage_flags": {
            "has_signaling": bool(summary.get("protocols")),
            "has_rtp": "RTP" in summary.get("protocols", []),
            "has_diameter": "DIAMETER" in [p.upper() for p in summary.get("protocols", [])],
            "has_gtp": any("GTP" in p.upper() for p in summary.get("protocols", [])),
            "has_sip": "SIP" in summary.get("protocols", []),
            "capture_point_type": summary.get("capture_point", {}).get("point", "UNKNOWN"),
        },
        
        # Health assessment
        "health": {
            "score": rca.get("health_score", 0) if isinstance(rca, dict) else 0,
            "status": rca.get("health_status", "unknown") if isinstance(rca, dict) else "unknown",
            "classification": rca.get("classification", "UNKNOWN") if isinstance(rca, dict) else "UNKNOWN",
        },
        
        # Key findings from RCA
        "network_overview": rca.get("network_overview", "") if isinstance(rca, dict) else "",
        
        "observations": (rca.get("observations", [])[:10] if isinstance(rca, dict) else []),
        
        "root_causes": (rca.get("root_causes", [])[:5] if isinstance(rca, dict) else []),
        
        "inconclusive_aspects": (rca.get("inconclusive_aspects", [])[:5] if isinstance(rca, dict) else []),
        
        "recommendations": (rca.get("recommendations", [])[:5] if isinstance(rca, dict) else []),
        
        # Session analysis
        "session_analysis": rca.get("session_analysis", {}) if isinstance(rca, dict) else {},
        
        # Voice/IMS stats
        "voice_stats": voice_stats,
        "voice_findings": voice_findings,
        
        # Top flows
        "top_flows": compact_flows,
        
        # Telecom sessions summary
        "telecom_sessions": [
            {
                "type": s.get("type", "Unknown"),
                "flow_count": s.get("flow_count", 0),
                "total_packets": s.get("total_packets", 0),
            }
            for s in results.get("telecom_sessions", [])[:10]
        ],
    }
    
    return context


def context_to_json(context: Dict[str, Any], indent: bool = False) -> str:
    """
    Convert context to JSON string for prompt injection.
    
    Args:
        context: The context dict
        indent: Whether to pretty-print (increases token count)
        
    Returns:
        JSON string
    """
    try:
        if indent:
            return json.dumps(context, indent=2, default=str)
        else:
            return json.dumps(context, separators=(',', ':'), default=str)
    except Exception as e:
        logger.error(f"Failed to serialize context: {e}")
        return json.dumps({"error": "Context serialization failed"})


def get_absent_protocols(context: Dict[str, Any]) -> List[str]:
    """
    Determine which common protocols are NOT in this capture.
    Useful for explaining limitations.
    """
    observed = set(p.upper() for p in context.get("capture_summary", {}).get("observed_protocols", []))
    
    common_protocols = {"SIP", "RTP", "DIAMETER", "GTP", "PFCP", "S1AP", "NGAP", "SCTP", "HTTP2"}
    
    return list(common_protocols - observed)
