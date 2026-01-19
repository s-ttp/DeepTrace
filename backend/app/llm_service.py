"""Kimi K2 LLM integration for PCAP analysis enrichment"""
import os
import json
import hashlib
import logging
from typing import List, Dict, Any
import httpx
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Initialize OpenAI client
client = None

def get_llm_client():
    """Get or create LLM client"""
    global client
    if client is None:
        # Check for OpenAI Key first for GPT-5.2 support
        openai_key = os.getenv("OPENAI_API_KEY")
        if openai_key:
             # Use Standard OpenAI Configuration
             base_url = os.getenv("OPENAI_BASE_URL") # None by default (uses api.openai.com)
             http_client = httpx.Client()
             client = OpenAI(
                api_key=openai_key,
                base_url=base_url,
                http_client=http_client
             )
             logger.info(f"Initialized OpenAI client (Standard Base URL)")
        
        else:
            # Fallback to Moonshot/Kimi
            moonshot_key = os.getenv("MOONSHOT_API_KEY")
            if not moonshot_key:
                 logger.error("No MOONSHOT_API_KEY or OPENAI_API_KEY found")
                 raise ValueError("API Key not set")
            
            http_client = httpx.Client()
            base_url = os.getenv("KIMI_API_BASE_URL", "https://api.moonshot.ai/v1")
            client = OpenAI(
                api_key=moonshot_key, 
                base_url=base_url,
                http_client=http_client
            )
            logger.info(f"Initialized Moonshot client (Base: {base_url})")
    
    return client

# Simple in-memory cache
llm_cache: Dict[str, str] = {}


def get_cache_key(prompt: str) -> str:
    """Generate cache key from prompt"""
    return hashlib.md5(prompt.encode()).hexdigest()


async def enrich_with_llm(flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich flows with LLM-generated insights
    
    Args:
        flows: List of flow dictionaries
        
    Returns:
        List of flows with added LLM insights
    """
    logger.info(f"Enriching {len(flows)} flows with LLM insights")
    
    enriched = []
    # Use configured model or default to gpt-5.2 for OpenAI, kimi for Moonshot
    default_model = "gpt-5.2" if os.getenv("OPENAI_API_KEY") else "kimi-k2-turbo-preview"
    model = os.getenv("OPENAI_MODEL", os.getenv("KIMI_MODEL", default_model))
    
    # Only analyze top flows to limit API calls (POC)
    flows_to_analyze = flows[:10]
    
    for i, flow in enumerate(flows_to_analyze):
        flow_copy = flow.copy()
        
        try:
            prompt = f"""Analyze this network flow from a mobile telecom PCAP capture:

Protocol: {flow.get('protocol', 'Unknown')}
Technology: {flow.get('primary_tech', 'Unknown')}
Source: {flow.get('src_ip', 'N/A')}:{flow.get('src_port', 'N/A')}
Destination: {flow.get('dst_ip', 'N/A')}:{flow.get('dst_port', 'N/A')}
Transport: {flow.get('transport', 'Unknown')}
Packets: {flow.get('packet_count', 0)}
Bytes: {flow.get('total_bytes', 0)}
Duration: {flow.get('duration', 0):.3f} seconds
Packets/sec: {flow.get('pps', 0)}
Is GTP: {flow.get('is_gtp', False)}
GTP TEIDs: {flow.get('gtp_teids', [])}
Is Diameter: {flow.get('is_diameter', False)}

Provide a brief analysis (2-3 sentences) covering:
1. What type of mobile network traffic this likely represents (2G/3G/4G/5G)
2. Whether the metrics look normal or unusual for this protocol
3. Any telecom-specific observations (interface type, signaling vs user plane, etc.)"""

            cache_key = get_cache_key(prompt)
            
            if cache_key in llm_cache:
                logger.debug(f"Cache hit for flow {i}")
                flow_copy["llm_insight"] = llm_cache[cache_key]
            else:
                llm_client = get_llm_client()
                
                # GPT-5.2 API usage
                if model == "gpt-5.2":
                    completion = llm_client.responses.create(
                        model=model,
                        input=f"You are a telecom network expert. {prompt}",
                        reasoning={
                            "effort": "low" # Quick insight
                        },
                        max_output_tokens=500
                    )
                    insight = completion.output_text
                else:
                    # Legacy/Standard API
                    completion = llm_client.chat.completions.create(
                        model=model,
                        messages=[
                            {
                                "role": "system", 
                                "content": "You are a telecom network expert specializing in mobile network protocols across all generations (2G/GSM, 3G/UMTS, 4G/LTE, 5G/NR). You understand protocols like GTP-U/C, PFCP, Diameter, S1-AP, NGAP, SIP, RTP, M3UA, SS7, and RADIUS. Analyze network flows concisely and provide actionable insights about mobile network traffic."
                            },
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.6,
                        max_tokens=200
                    )
                    insight = completion.choices[0].message.content
                flow_copy["llm_insight"] = insight
                llm_cache[cache_key] = insight
                logger.debug(f"LLM insight generated for flow {i}")
                
        except Exception as e:
            logger.error(f"Error getting LLM insight for flow {i}: {e}")
            flow_copy["llm_insight"] = f"Analysis unavailable: {str(e)}"
        
        enriched.append(flow_copy)
    
    # Add remaining flows without LLM insights
    for flow in flows[10:]:
        flow_copy = flow.copy()
        flow_copy["llm_insight"] = "Not analyzed (limit reached for POC)"
        enriched.append(flow_copy)
    
    return enriched


# ============================================================================
# GPT-5.2 Advanced Features: Adaptive Reasoning & Tool Calling
# ============================================================================

def determine_reasoning_effort(
    failure_summary: Dict[str, Any] = None,
    voice_context: Dict[str, Any] = None,
    flows: List[Dict[str, Any]] = None,
    expert_findings: List[Dict[str, Any]] = None
) -> str:
    """
    Determine appropriate reasoning effort based on trace complexity.
    
    Returns:
        "low" - Simple traces, few issues
        "medium" - Moderate complexity
        "high" - Complex failures requiring deep analysis
    """
    complexity_score = 0
    
    # Factor 1: Number of failures
    if failure_summary:
        failure_count = len(failure_summary.get("failures", []))
        if failure_count > 5:
            complexity_score += 3
        elif failure_count > 2:
            complexity_score += 2
        elif failure_count > 0:
            complexity_score += 1
    
    # Factor 2: Call classifications (REJECTED = complex)
    if voice_context:
        classifications = voice_context.get("call_classifications", {})
        if classifications.get("REJECTED", 0) > 0:
            complexity_score += 3
        if classifications.get("EARLY_DROP", 0) > 0:
            complexity_score += 2
        if classifications.get("INCOMPLETE", 0) > 0:
            complexity_score += 1
    
    # Factor 3: Number of flows
    if flows:
        flow_count = len(flows)
        if flow_count > 100:
            complexity_score += 2
        elif flow_count > 50:
            complexity_score += 1
    
    # Factor 4: Expert findings (TShark warnings)
    if expert_findings:
        if len(expert_findings) > 10:
            complexity_score += 2
        elif len(expert_findings) > 5:
            complexity_score += 1
    
    # Map score to effort level
    if complexity_score >= 6:
        return "high"
    elif complexity_score >= 3:
        return "medium"
    else:
        return "low"


# Tool definitions for GPT-5.2 tool calling
RCA_TOOLS = [
    {
        "type": "function",
        "name": "get_rtp_quality_details",
        "description": "Retrieve detailed RTP quality metrics (jitter, packet loss, MOS) for a specific call or all calls in the trace. Use this when you need concrete voice quality data.",
        "parameters": {
            "type": "object",
            "properties": {
                "call_id": {
                    "type": "string",
                    "description": "The Call-ID to get RTP metrics for. Use 'all' for aggregate metrics."
                }
            },
            "required": ["call_id"]
        }
    },
    {
        "type": "function",
        "name": "get_failure_details",
        "description": "Get detailed information about specific failure codes or error messages observed in the trace.",
        "parameters": {
            "type": "object",
            "properties": {
                "failure_type": {
                    "type": "string",
                    "description": "Type of failure to investigate: 'sip_errors', 'diameter_errors', 'gtp_errors', 'pfcp_errors'"
                }
            },
            "required": ["failure_type"]
        }
    },
    {
        "type": "function",
        "name": "get_call_flow_details",
        "description": "Get the complete SIP message sequence for a specific call to understand the exact flow.",
        "parameters": {
            "type": "object",
            "properties": {
                "call_id": {
                    "type": "string",
                    "description": "The Call-ID to get the message flow for."
                }
            },
            "required": ["call_id"]
        }
    }
]


def handle_tool_call(tool_name: str, tool_args: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Handle tool calls from GPT-5.2 by retrieving requested data from context.
    
    Args:
        tool_name: Name of the tool being called
        tool_args: Arguments passed to the tool
        context: Full analysis context containing all available data
        
    Returns:
        String response to feed back to the model
    """
    logger.info(f"Tool call: {tool_name} with args: {tool_args}")
    
    if tool_name == "get_rtp_quality_details":
        rtp_context = context.get("rtp_quality_context", "")
        if rtp_context:
            return f"RTP Quality Data:\n{rtp_context}"
        else:
            return "RTP quality data not available - media plane may not have been captured at this observation point."
    
    elif tool_name == "get_failure_details":
        failure_type = tool_args.get("failure_type", "")
        failure_summary = context.get("failure_summary", {})
        
        if failure_type == "sip_errors":
            sip_errors = [f for f in failure_summary.get("failures", []) if "SIP" in str(f)]
            return f"SIP Errors Found: {json.dumps(sip_errors, indent=2)}" if sip_errors else "No SIP errors found."
        elif failure_type == "diameter_errors":
            diameter_errors = [f for f in failure_summary.get("failures", []) if "Diameter" in str(f)]
            return f"Diameter Errors Found: {json.dumps(diameter_errors, indent=2)}" if diameter_errors else "No Diameter errors found."
        elif failure_type == "gtp_errors":
            gtp_errors = [f for f in failure_summary.get("failures", []) if "GTP" in str(f)]
            return f"GTP Errors Found: {json.dumps(gtp_errors, indent=2)}" if gtp_errors else "No GTP errors found."
        elif failure_type == "pfcp_errors":
            pfcp_errors = [f for f in failure_summary.get("failures", []) if "PFCP" in str(f)]
            return f"PFCP Errors Found: {json.dumps(pfcp_errors, indent=2)}" if pfcp_errors else "No PFCP errors found."
        else:
            return f"Unknown failure type: {failure_type}. Use: sip_errors, diameter_errors, gtp_errors, pfcp_errors"
    
    elif tool_name == "get_call_flow_details":
        call_id = tool_args.get("call_id", "")
        voice_context = context.get("voice_context", {})
        calls = voice_context.get("calls", [])
        
        for call in calls:
            if call.get("call_id") == call_id:
                return f"Call Flow for {call_id}:\n{json.dumps(call, indent=2, default=str)}"
        
        return f"Call-ID {call_id} not found. Available calls: {[c.get('call_id', 'unknown')[:20] for c in calls[:5]]}"
    
    else:
        return f"Unknown tool: {tool_name}"


async def root_cause_analysis(
    flows: List[Dict[str, Any]], 
    summary: Dict[str, Any] = None,
    correlated_sessions: List[Dict[str, Any]] = None,
    failure_summary: Dict[str, Any] = None,
    expert_findings: List[Dict[str, Any]] = None,
    transactions: List[Dict[str, Any]] = None,
    procedure_kpis: Dict[str, Any] = None,
    voice_context: Dict[str, Any] = None,
    temporal_context: str = None,
    subscriber_context: str = None,
    # New VoLTE enhancement contexts
    codec_context: str = None,
    ringback_context: str = None,
    precondition_context: str = None,
    rtp_quality_context: str = None,
    session_timer_context: str = None,
    transfer_context: str = None,
    handover_context: str = None,
    vendor_context: str = None  # NEW: Vendor-specific code mappings
) -> Dict[str, Any]:
    """
    Enhanced AI Analysis: Returns structured RCA with sections for
    observations, diagnosis, and recommendations.
    
    Returns a dictionary with:
    - network_overview: High-level summary
    - observations: List of key findings
    - root_cause: Identified issues
    - recommendations: Actionable suggestions
    - health_score: Overall network health (0-100)
    """
    logger.info("Performing enhanced root cause analysis")
    
    default_model = "gpt-5.2" if os.getenv("OPENAI_API_KEY") else "kimi-k2-turbo-preview"
    model = os.getenv("OPENAI_MODEL", os.getenv("KIMI_MODEL", default_model))
    
    # Build summary if not provided
    if summary is None:
        summary = {
            "total_flows": len(flows),
            "total_packets": sum(f.get("packet_count", 0) for f in flows),
            "total_bytes": sum(f.get("total_bytes", 0) for f in flows),
            "protocols": list(set(f.get("protocol", "Unknown") for f in flows)),
        }
    
    # Calculate basic metrics for health scoring
    technologies = list(set(f.get("primary_tech", "Unknown") for f in flows if f.get("primary_tech")))
    gtp_flows = [f for f in flows if f.get("is_gtp")]
    diameter_flows = [f for f in flows if f.get("is_diameter")]
    
    # Limit transactions for prompt
    top_transactions = transactions[:40] if transactions else []

    
    # 3. Contextual Voice Logic
    voice_guidance = ""
    if voice_context:
        trace_type = voice_context.get("trace_type", "UNKNOWN")
        if trace_type == "REGISTRATION_ONLY":
            voice_guidance = """
            - **REGISTRATION ONLY**: This trace contains NO Voice Calls (INVITE). It only contains IMS Registrations.
            - **DO NOT** mention "Call Drops" or "Media Issues".
            - Focus on Registration Success/Failure (401/403 Challenge loops are normal if resolved).
            """
        elif trace_type == "CALLS_AND_REGISTRATIONS":
             voice_guidance = """
             - **Calls Detected**: Analyze Call Drops and Media Issues.
             - **Drop**: If BYE sent immediately after OK, or Error Code present.
             - **One-Way**: If 'media_findings' show RTP missing in one direction.
             - **Silence**: If 'media_findings' show low packet rate.
             """

    prompt = f"""You are a telecom root cause analysis engine.

## STRICT RULES (MANDATORY):
1. You may ONLY use protocols, messages, and fields that are explicitly present in the provided evidence.
2. If a protocol is not listed as observed, you MUST NOT reference it.
   - Example: If DIAMETER is absent from protocols detected, you MUST NOT mention HSS, S6a, Cx, or user-unknown errors.
3. Absence of evidence (e.g., no RTP observed) does NOT imply failure of that layer.
   - You may only state: "Not observable at this capture point."
4. Every root cause MUST cite concrete packet-level evidence (message type, response code, timing).
5. If multiple explanations are possible but unprovable, you MUST choose:
   - "Inconclusive from this capture"
   - and list what additional capture would be required.
6. If a cause code is labeled "UNMAPPED(xxx)", you MUST NOT invent or guess its meaning.
   - State: "Cause code xxx is not in standard 3GPP/Wireshark mappings (vendor-specific or proprietary)."
   - Do NOT assume vendor behavior unless explicitly provided in a vendor overlay.

## CAPTURE STATISTICS
- Total Flows: {summary.get('total_flows', len(flows))}
- Total Packets: {summary.get('total_packets', 0):,}
- Total Data: {summary.get('total_bytes', 0):,} bytes
- Protocols Detected: {', '.join(summary.get('protocols', []))}
- Technologies Present: {', '.join(technologies) if technologies else 'Unknown'}
- GTP Tunnels: {len(gtp_flows)}
- Diameter Sessions: {len(diameter_flows)}
- Capture Duration: {summary.get('duration', 0):.2f}s

## CAPTURE POINT CONTEXT
{f"- Observation Point: {summary.get('capture_point', {}).get('point', 'UNKNOWN')}" if summary.get('capture_point') else "- Observation Point: UNKNOWN"}
{f"- Description: {summary.get('capture_point', {}).get('description', 'N/A')}" if summary.get('capture_point') else ""}
{f"- Expected Protocols: {', '.join(summary.get('capture_point', {}).get('expected', []))}" if summary.get('capture_point') else ""}
{f"- NOT Expected (do not flag as missing): {', '.join(summary.get('capture_point', {}).get('not_expected', []))}" if summary.get('capture_point') else ""}

## SIP TIMING KPIs
{json.dumps(voice_context.get('sip_kpis', {}), indent=2) if voice_context and voice_context.get('sip_kpis') else "No SIP timing data available."}

## CALL CLASSIFICATIONS
{json.dumps(voice_context.get('call_classifications', {}), indent=2) if voice_context and voice_context.get('call_classifications') else "No call classification data."}

## COVERAGE FLAGS
{json.dumps(voice_context.get('coverage_flags', {}), indent=2) if voice_context and voice_context.get('coverage_flags') else "No coverage assessment available."}

**COVERAGE FLAG RULES**:
- If coverage_flags.rtp_presence == "NOT_OBSERVED": Do NOT diagnose audio quality issues. State: "Media plane not captured at this observation point."
- If coverage_flags.rtp_presence == "UNIDIRECTIONAL": May indicate one-way audio, but verify SDP direction attributes first.

## VOICE & IMS ANALYSIS
{json.dumps(voice_context, indent=2) if voice_context else "No Voice/IMS calls detected."}

## FAILURES & ERRORS (Scapy)
{json.dumps(failure_summary, indent=2) if failure_summary else "No specific failures detected."}

## EXPERT PROTOCOL FINDINGS (TShark)
{json.dumps(expert_findings, indent=2) if expert_findings else "No expert warnings."}

## PROCEDURE KPIs (Success Rates & Latency)
{json.dumps(procedure_kpis, indent=2) if procedure_kpis else "No procedure statistics available."}

{temporal_context if temporal_context else "## TEMPORAL ANOMALIES: No temporal anomalies detected."}

{subscriber_context if subscriber_context else "## SUBSCRIBER CORRELATION: No subscriber identities detected."}

{codec_context if codec_context else "## CODEC NEGOTIATION: No codec negotiation data available."}

{ringback_context if ringback_context else "## RINGBACK DIAGNOSIS: No ringback analysis performed."}

{precondition_context if precondition_context else "## PRECONDITION STATUS: No QoS precondition data available."}

{rtp_quality_context if rtp_quality_context else "## RTP QUALITY: No RTP quality metrics available (media plane may not be captured)."}

{session_timer_context if session_timer_context else "## SESSION TIMER: No session timer data detected."}

{transfer_context if transfer_context else "## CALL TRANSFER: No call transfer (REFER/NOTIFY) detected."}

{handover_context if handover_context else "## SRVCC/CSFB DETECTION: No PS→CS handover or CS Fallback indicators detected."}

{vendor_context if vendor_context else "## VENDOR CODE MAPPINGS: No vendor-specific code mappings available."}

## DEEP TRANSACTIONS (Sample)
{json.dumps(top_transactions, indent=2, default=str) if top_transactions else "No detailed transactions available."}

## CORRELATED SESSIONS
{json.dumps(correlated_sessions[:5] if correlated_sessions else [], indent=2, default=str)}

## TOP FLOWS (by volume)
{json.dumps(flows[:8], indent=2, default=str)}

---

## 3GPP PATTERN RECOGNITION PHASE
Based on observed cause codes and protocol sequences, identify any standard 3GPP-defined failure scenarios that match the evidence. Use your knowledge of:
- 3GPP TS 24.301 (NAS EMM/ESM causes)
- 3GPP TS 29.274 (GTPv2-C causes)
- 3GPP TS 29.244 (PFCP causes)
- 3GPP TS 38.413/36.413 (NGAP/S1AP causes)
- 3GPP TS 29.229/29.272 (Diameter result codes)
- RFC 3261 (SIP response codes)

For each pattern match:
1. Name the standard failure pattern (e.g., "EPS Attach Reject - IMSI Unknown")
2. Cite the 3GPP/RFC specification reference
3. List the specific evidence from THIS capture that triggered the match
4. Confidence: HIGH only if ALL expected symptoms are present

**IMPORTANT**: Only match patterns where concrete evidence exists. If a cause code is "UNMAPPED(xxx)", do NOT attempt to match it to a pattern.

---

**CONFIDENCE SCORING GUIDELINES**:
Score each root cause with a confidence percentage:
- 90-100%: Direct evidence (explicit reject/error code observed)
- 70-89%: Strong correlation (timeout + retransmissions, matching timestamps)
- 50-69%: Circumstantial (unusual patterns, inferred from related issues)
- <50%: Speculation (no direct evidence, hypothesis only)

**OUTPUT REQUIREMENTS**:
- Classification: {{ESTABLISHED, CANCELLED_BY_CALLER, REJECTED, INCOMPLETE, INCONCLUSIVE}}
- Root Cause (only if provable with concrete evidence)
- Confidence percentage and justification for each finding
- Evidence (exact protocol messages, response codes, and timing)
- What CANNOT be concluded from this capture

**VOICE/IMS GUIDANCE**:
{voice_guidance}

Provide a STRUCTURED analysis with the following JSON format (respond ONLY with valid JSON):

{{
  "network_overview": "A 2-3 sentence executive summary based ONLY on observed protocols and messages",
  "classification": "ESTABLISHED|CANCELLED_BY_CALLER|REJECTED|INCOMPLETE|INCONCLUSIVE",
  "health_score": <number 0-100>,
  "health_status": "healthy|warning|critical",
  "pattern_matches": [
    {{
      "pattern_name": "Standard 3GPP failure pattern name",
      "spec_reference": "3GPP TS xx.xxx Section x.x.x or RFC xxxx",
      "evidence": ["Cause code: X", "Message: Y", "Sequence: Z"],
      "confidence": "HIGH|MEDIUM|LOW",
      "explanation": "Why this pattern matches the observed evidence"
    }}
  ],
  "observations": [
    {{"category": "Traffic Pattern", "finding": "description with evidence", "severity": "info|warning|critical", "evidence": "specific message/field"}}
  ],
  "root_causes": [
    {{
        "issue": "issue title", 
        "description": "detailed description with ONLY observed evidence", 
        "impact": "what this affects", 
        "confidence_pct": <number 0-100>,
        "confidence_level": "HIGH|MEDIUM|LOW",
        "confidence_justification": "Why this confidence level (what evidence supports or is missing)",
        "evidence_refs": ["Exact message: SIP/INVITE", "Response code: 503", "Timestamp: 12.345s"]
    }}
  ],
  "inconclusive_aspects": [
    {{"aspect": "what cannot be determined", "reason": "why (missing protocol/field)", "additional_capture_needed": "what would clarify this"}}
  ],
  "recommendations": [
    {{"priority": 1, "action": "what to do", "rationale": "why this helps based on evidence", "category": "Performance|Security|Reliability|Optimization"}}
  ],
  "session_analysis": {{
    "signaling_health": "description based ONLY on observed signaling protocols",
    "user_plane_health": "description based ONLY on observed user plane traffic",
    "voice_quality": "description based ONLY on observed IMS/RTP (or 'Not observable')",
    "cross_plane_correlation": "correlation based ONLY on observed data"
  }},
  "sequence_diagram": "mermaid sequence diagram code (string) visualizing observed message flow. Use 'sequenceDiagram' header. Include ONLY observed protocols."
}}

CRITICAL: Do NOT mention protocols, response codes, or failure reasons that are not explicitly present in the evidence above. If insufficient evidence exists, use classification "INCONCLUSIVE" and populate "inconclusive_aspects"."""

    try:
        llm_client = get_llm_client()
        
        if False and model == "gpt-5.2": # Disabled to prevent duplication, using logic in else block
             completion = llm_client.responses.create(
                model=model,
                input=f"You are an expert telecom network analyst AI.\n\n{prompt}\n\nYou MUST respond with valid JSON only.",
                reasoning={
                    "effort": "high" # Deep RCA
                }
            )
             response_text = completion.output_text.strip()
        else:
            # Prepare arguments
            completion_args = {
                "model": model,
                "messages": [
                    {
                        "role": "system", 
                        "content": "You are an expert telecom network analyst AI. You MUST respond with valid JSON only. Your expertise covers: Mobile network protocols (GTP-U/C, PFCP, Diameter, S1-AP, NGAP), Voice protocols (SIP, RTP, VoLTE), Legacy (SS7, M3UA), and Supporting protocols (DNS, RADIUS, DHCP, HTTP/2 for 5G-SBI). Analyze network captures with precision and provide actionable insights."
                    },
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3
            }
            
            if model == "gpt-5.2":
                 # Use new responses API for GPT-5.2
                 # Construct input prompt from messages
                 system_msg = next((m["content"] for m in completion_args["messages"] if m["role"] == "system"), "")
                 user_msg = next((m["content"] for m in completion_args["messages"] if m["role"] == "user"), "")
                 full_input = f"{system_msg}\n\nUser Request:\n{user_msg}"
                 
                 # Determine adaptive reasoning effort
                 reasoning_effort = determine_reasoning_effort(
                     failure_summary=failure_summary,
                     voice_context=voice_context,
                     flows=flows,
                     expert_findings=expert_findings
                 )
                 logger.info(f"Adaptive reasoning effort: {reasoning_effort}")
                 
                 # Build context for tool calls
                 tool_context = {
                     "rtp_quality_context": rtp_quality_context,
                     "failure_summary": failure_summary,
                     "voice_context": voice_context,
                     "flows": flows,
                     "handover_context": handover_context
                 }
                 
                 # Initial API call with tools
                 completion = llm_client.responses.create(
                    model=model,
                    input=full_input,
                    reasoning={"effort": reasoning_effort},
                    max_output_tokens=8000,
                    tools=RCA_TOOLS
                 )
                 
                 # Handle tool calling loop (max 3 iterations to prevent infinite loops)
                 max_tool_iterations = 3
                 iteration = 0
                 
                 while iteration < max_tool_iterations:
                     # Check if model wants to call tools
                     tool_calls = []
                     for output_item in completion.output:
                         if hasattr(output_item, 'type') and output_item.type == 'function_call':
                             tool_calls.append(output_item)
                     
                     if not tool_calls:
                         # No tool calls, model is done
                         break
                     
                     logger.info(f"Tool calls requested: {len(tool_calls)}")
                     
                     # Process each tool call and collect results
                     tool_results = []
                     for tool_call in tool_calls:
                         tool_name = tool_call.name
                         tool_args = json.loads(tool_call.arguments) if isinstance(tool_call.arguments, str) else tool_call.arguments
                         result = handle_tool_call(tool_name, tool_args, tool_context)
                         tool_results.append({
                             "type": "function_call_output",
                             "call_id": tool_call.call_id,
                             "output": result
                         })
                     
                     # Continue conversation with tool results
                     completion = llm_client.responses.create(
                         model=model,
                         previous_response_id=completion.id,
                         input=tool_results,
                         reasoning={"effort": reasoning_effort},
                         max_output_tokens=8000,
                         tools=RCA_TOOLS
                     )
                     
                     iteration += 1
                 
                 response_text = completion.output_text.strip()
            
            else:
                # O1 models use max_completion_tokens
                if model.startswith("o1"):
                    completion_args["max_completion_tokens"] = 3000
                else:
                    completion_args["max_tokens"] = 3000

                completion = llm_client.chat.completions.create(**completion_args)
                response_text = completion.choices[0].message.content.strip()
        
        # Try to parse JSON response
        try:
            # Clean up response if it has markdown code blocks
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            
            rca_data = json.loads(response_text.strip())
            
            # --- STRICT VALIDATION (Adapted for App Schema) ---
            required_keys = {"classification", "root_causes", "network_overview"}
            missing = required_keys - rca_data.keys()
            if missing:
                error_msg = f"RCA missing required keys: {missing}"
                logger.error(error_msg)
                raise ValueError(error_msg)
            # Sanitize Mermaid code to prevent syntax errors
            if "sequence_diagram" in rca_data and isinstance(rca_data["sequence_diagram"], str):
                 # Semicolons can break Mermaid message parsing, replace with commas
                 rca_data["sequence_diagram"] = rca_data["sequence_diagram"].replace(";", ",")
                 
            logger.info("Enhanced structured RCA completed")
            return rca_data
            
        except json.JSONDecodeError as je:
            logger.warning(f"Failed to parse RCA JSON: {je}, using fallback format")
            # Return structured fallback with the raw text
            return {
                "network_overview": response_text[:500] if len(response_text) > 500 else response_text,
                "health_score": 75,
                "health_status": "warning",
                "observations": [
                    {"category": "Analysis", "finding": "Structured analysis parsing failed, raw insights provided", "severity": "info"}
                ],
                "root_causes": [],
                "recommendations": [
                    {"priority": 1, "action": "Review raw analysis above", "rationale": "Manual review needed", "category": "Optimization"}
                ],
                "session_analysis": {
                    "signaling_health": "See overview",
                    "user_plane_health": "See overview", 
                    "cross_plane_correlation": "See overview"
                },
                "sequence_diagram": "",
                "raw_analysis": response_text
            }
        
    except Exception as e:
        logger.error(f"Error performing RCA: {e}")
        return {
            "network_overview": f"Analysis could not be completed: {str(e)}",
            "health_score": 0,
            "health_status": "critical",
            "observations": [
                {"category": "Error", "finding": f"LLM API error: {str(e)}", "severity": "critical"}
            ],
            "root_causes": [
                {"issue": "API Error", "description": str(e), "impact": "Analysis unavailable", "confidence_pct": 0, "confidence_level": "LOW", "confidence_justification": "Unable to analyze due to API error"}
            ],
            "recommendations": [
                {"priority": 1, "action": "Check LLM API configuration", "rationale": "API connectivity issue", "category": "Reliability"}
            ],
            "session_analysis": {
                "signaling_health": "Unknown",
                "user_plane_health": "Unknown",
                "cross_plane_correlation": "Unknown"
            },
            "sequence_diagram": ""
        }
